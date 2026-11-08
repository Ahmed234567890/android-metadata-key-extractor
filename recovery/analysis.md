# Data-recovery triage — findings

Read-only inspection of the images extracted from the SM-A032F after the
`init_user0_failed` recovery. All work was done on the host; the images were
opened read-only and never modified.

## 1. `/data` is dm-default-key ciphertext

`userdata.img` (26,755,444,828 B) has:

- no sparse-image magic (`3a ff 26 ed`);
- no GPT header at offset 512;
- no ext4 magic at `0x438` (`53 ef`);
- no f2fs magic at `0x400` (`10 20 f5 f2`);
- no filesystem magic at any 512-aligned offset in the first 4 MiB;
- high-entropy content from byte 0.

That is the signature of Android **metadata encryption**: the whole `/data`
block device is encrypted with `dm-default-key` (AES-256-XTS, 512-byte
sectors), so even the f2fs superblock is ciphertext. This is not file-based
encryption (FBE), where the superblock would be visible.

`userdata.trim.img` is the same data trimmed to the exact partition size
(26,755,444,736 B).

`userdata_encrypted.img` (10,402,595,840 B) is a **second, partial dump**, not
a prefix of the full image: it matches `userdata.img` for the first
4,472,589,825 bytes and then diverges. It is a snapshot taken at a different
time. Preserve it; if one snapshot has a damaged region, the other may hold the
pre-damage ciphertext for that sector.

## 2. The key is in `/metadata`, but it is TEE-wrapped

`metadata.img` is ext4 (UUID `0cb00f4b-30cd-4841-bcfc-d47caa64dfb2`). Under
`/vold/metadata_encryption/key/`:

| File | Size | Meaning |
| --- | --- | --- |
| `version` | 1 B | `1` |
| `secdiscardable` | 16,384 B | auxiliary random data; not the metadata key |
| `keymaster_key_blob` | 234 B | TrustKernel TEE key blob, magic `pKMblob` |
| `encrypted_key` | 92 B | 12-byte IV + 64-byte ciphertext + 16-byte GCM tag |

The 64-byte plaintext is the metadata key (AES-256-XTS uses two 32-byte keys).
It is encrypted with an AES-GCM key that lives **inside the phone's TEE**; the
TEE key is represented by `keymaster_key_blob`. There is no plaintext key
anywhere in `metadata.img`.

Key file timestamps are `18-Jul-2026 20:36` — the original setup time, not the
failure date. A read-only `e2fsck` and a journal replay on a copy both leave the
four key files byte-identical, so the key was not rotated and still matches the
ciphertext.

Hashes (for integrity only; not reversible):

```
version            6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b
secdiscardable     5a967a7777ff6e08b5d15c3f75ddb198c85c5b364eaf5ec99ab28e1d56bd31b4
keymaster_key_blob 5a24fbbbd2475bc6f988868a4ba7c411fa14b05faa4d5a54c042f9bc84806f25
encrypted_key      bf62a3f099f66036a88d82b81342016ece073033e0efad8ab56906d69dbef0fe
```

### Consequence

Offline decryption is **not feasible**: unwrapping `keymaster_key_blob`
requires the phone's TrustKernel TEE (hardware-bound). A PC has no way to
recover the 64-byte metadata key from these files alone. The only paths are
(a) boot the phone so its TEE can unwrap the key, or (b) a TEE/keymaster
exploit (not available here).

## 3. The boot image is the same build — not the mismatch

| Image | sha256 | Kernel | DTB | `init` |
| --- | --- | --- | --- | --- |
| `boot_p40_backup.img` (Magisk) | `0727cd39…` | `d8962f0f…` | `7db696ee…` | `magiskinit` 165,624 B; real init in `.backup/init.xz` |
| `bootchk/boot_unrooted.img` | `129308ed…` | `d8962f0f…` | `7db696ee…` | `86f4f141…` 1,286,364 B |

Decompressing Magisk's `.backup/init.xz` gives exactly `86f4f141…`, the same
`init` as the unrooted image. `fstab.m168` is byte-identical in both ramdisks.
Magisk's config says `KEEPFORCEENCRYPT=true`, `KEEPVERITY=true`.

**Conclusion:** flashing the unrooted image did not introduce a build, kernel,
DTB, or fstab mismatch. The unrooted image is the correct boot stack for this
build. The failure is therefore in `/data` itself (most likely f2fs corruption)
or in keymaster/TEE, not in the boot image.

## 4. What the failure record says

`misc_p8_backup.img` (the `/misc` partition) contains:

```
boot-recovery
recovery
--prompt_and_wipe_data
--reason=init_user0_failed
```

`/metadata/bootstat/persist.sys.boot.reason` is `recovery`. The recovery fstab
mounts `/data` as `f2fs /dev/block/by-name/userdata` with **no encryption
flags**, and `ro.crypto.dm_default_key.options_format.version=2`. Recovery
cannot set up `dm-default-key`, so its raw f2fs mount of `mmcblk0p55` fails with
`Magic Mismatch, valid(0xf2f52010) - read(0x6838b374)`. That is expected for
ciphertext and is **not** the root cause.

The normal-boot log that wrote `init_user0_failed` was overwritten by the
recovery logs; all saved `last_kmsg*` files are recovery sessions. The
`sprd-sblock` errors in `last_kmsg.7` are audio DSP channels (5-13, 5-17), not
keymaster, so they do not prove a TEE failure.

Most likely causes, in order:

1. `/data` f2fs corruption after the bootloop and repeated hard reboots. Android
   runs `fsck.f2fs` before mounting; if repair fails, `vold` cannot mount
   `/data` and user 0 cannot be initialized.
2. A keymaster/TEE failure preventing the metadata key from being unwrapped.
3. A `/vendor` fstab/HAL mismatch (not observed; `/vendor` was not extracted).

## 5. Recovery options (when the phone is available)

### A. Boot the original boot stack and capture the real log

The unrooted image is the same build, so it is safe to boot. If it still drops
to recovery:

- capture the normal-boot kernel log before recovery overwrites it
  (`/proc/last_kmsg`, pstore/ramoops, or `adb` if adbd starts);
- look for `fsck.f2fs`, `dm-default-key`, `keymaster`, `metadata_encryption`,
  and `Failed to mount /data`.

That log decides between "filesystem corruption" and "key failure".

### B. TWRP / custom recovery

A device tree exists: `almondnguyen/twrp_device_samsung_a3core` (based on
`A032FXXU4CWI8`). Prebuilt images are reported to bootloop or have touch
issues; for recovery, ADB-only is enough. If the build can talk to the vendor
keymaster HAL, it can decrypt `/data`, run `fsck.f2fs -f` on the decrypted
device, mount it, and `adb pull` the data.

### C. Minimal custom initramfs

Boot a ramdisk that starts the vendor keymaster HAL and `vold`, unwraps the
metadata key, sets up `dm-default-key`, runs `fsck.f2fs -f`, mounts `/data`,
and starts `adbd`. This is the most reliable path but needs the vendor
partition/blobs. It is essentially a purpose-built recovery.

### D. If the TEE is dead

If the log shows keymaster failure, the key cannot be unwrapped on that phone.
Options are a TEE/keymaster repair (service center / vendor tool) or a TEE
exploit. Do not wipe: the ciphertext and key blob are still the only copy.

## 6. What to pull once `/data` mounts

- Aegis: `/data/data/com.beemdevelopment.aegis/` (encrypted SQLite vault) and
  exported vaults in `/data/media/0/Aegis/`.
- Photos: `/data/media/0/DCIM/`.
- All user files: `/data/media/0/`.

The Aegis vault still needs the user's master password (or biometric-wrapped
key) to open; recovering the app data does not bypass that.
