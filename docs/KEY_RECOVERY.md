# SM-A032F — Metadata Key Recovery (step by step)

**Target**: Samsung Galaxy A03 Core (`SM-A032F`, Unisoc SC9863A, board `m168`)
**Build**: `AP2A.240905.003` / `A032FXXS9CZA2` (Android 14), `user/test-keys`
**Bootloader state**: `ro.boot.veritymode=enforcing`, `ro.boot.flash.locked=0`
**Device state during this phase**: Android 11 recovery (`RP1A.201005.001`, `userdebug/test-keys`,
kernel `4.14.199 #1 SMP PREEMPT Thu Aug 11 11:44:51 KST 2022 armv8l`), SELinux permissive, root shell
(`u:r:su:s0`), 32-bit-only userspace.

ADB serial: `R7SRC1W7MSF`.

---

## Goal

Recover the 64-byte Android metadata key that encrypts `/data` (userdata partition) via the
device's own TrustKernel TEE, so that the encrypted userdata image can be decrypted and the
data extracted — **without ever wiping, formatting, or writing to `/data` or `/metadata`**.

---

## Step 0 — Capture the raw images (read-only)

| Partition | Device | Image | Size |
| --- | --- | --- | --- |
| `/data` | `mmcblk0p55` | `userdata.img` | 26,755,444,828 B (dm-default-key ciphertext) |
| `/data` (trimmed) | `mmcblk0p55` | `userdata.trim.img` | 26,755,444,736 B |
| `/metadata` | `mmcblk0p45` | `metadata.img` | 16,777,298 B (ext4, TEE-wrapped key files) |
| `/metadata` (trimmed) | `mmcblk0p45` | `metadata.trim.img` | 16,777,216 B |
| `/misc` | — | `misc_p8_backup.img` | 1,048,576 B (`--prompt_and_wipe_data --reason=init_user0_failed`) |
| `boot` | `mmcblk0p40` | `boot_p40_backup.img` | 67,108,864 B (Magisk-patched) |
| `boot` | `mmcblk0p40` | `bootchk/boot_unrooted.img` | 67,108,864 B (flashed by user) |

All operations on these images were strictly read-only; recovery work was done on copies/CWs.

---

## Step 1 — Pull the TEE-wrapped key files from `/metadata`

Mounted `/dev/block/mmcblk0p45` at `/mnt/metadata` (ro).

Key files present:

| File | Size | Content |
| --- | --- | --- |
| `keymaster_key_blob` | 234 B | `pKMblob\0` + key type + 226 B inner blob |
| `encrypted_key` | 92 B | 12 B IV + 64 B ciphertext + 16 B GCM tag |
| `secdiscardable` | 16,384 B | discardable key blob |
| `version` | — | `"1"` |

Key file naming/hash facts are recorded in `recovery/hashes.txt`.

---

## Step 2 — Extract the 64-byte metadata key through the TEE (main breakthrough)

### 2.1 — TIPC transport to the Trusty keymaster TA

The HAL route was not usable (recovery has no binder/hwbinder/vndbinder devices), so the
Trusty keymaster TA (`com.android.trusty.keymaster`) was talked to directly over TIPC.

- TIPC `connect` to the TA returned 0 (alive).
- Command encoding: `cmd = N << 2`; response = `cmd | 3`.
- Commands used: `GET_VERSION=0x1c`, `CONFIGURE=0x48`, `UPGRADE_KEY=0x44`, `BEGIN=4`,
  `UPDATE=8`, `FINISH=0x0c`.

### 2.2 — Key params sent to `Configure`

Tags (wire value = tag id, little-endian u32):

| Tag | Value | Meaning |
| --- | --- | --- |
| `TAG_PURPOSE` | `0x20000001` | DECRYPT |
| `TAG_ALGORITHM` | `0x10000002` | AES-256-XTS |
| `TAG_BLOCK_MODE` | `0x20000004` | GCM |
| `TAG_PADDING` | `0x20000006` | NONE |
| `TAG_MIN_MAC_LENGTH` | `0x30000008` | 128 |
| `TAG_APPLICATION_ID` | `0x90000259` | appId (SHA512 of `"Android secdiscardable SHA512"` … \|\| secdiscardable) |
| `TAG_NONCE` | `0x900003E9` | 12-byte IV |
| `TAG_MAC_LENGTH` | `0x300003EB` | 128 |

### 2.3 — Key upgrade + decrypt

- `UPGRADE_KEY` with full key material raised the key's patchlevel to the latched `202601`.
- `BEGIN` → OK, returned op handle.
- `UPDATE` → **64-byte plaintext key** returned; `FINISH` → OK (GCM tag verified).

### 2.4 — Recovered key

Hex (64 bytes):

```
```

Saved to `recovery/keys/metadata_key.bin` (kept private; **not** published).

---

## Step 3 — Load a dm mapping that decrypts `/data`

Built static ARM32 dm-ioctl clients:

- `kmclient` — TIPC keymaster client (ARM32, static, freestanding).
- `dmclient` — creates a `dm-default-key` mapping via raw ioctl.
- `dmload` — generic dm table loader driven by a table spec.

`dm-default-key` table format:

```
<start> <length> default-key <cipher> <key> <iv_offset> <dev> <start> [<#opts> <opts>...]
```

Params used:

```
aes-xts-plain64 <128-hex> 0 /dev/block/mmcblk0p55 0 2 sector_size:4096 iv_large_sectors
```

Devices created:

- `/dev/mapper/userdata-dec` (dm-0, read-only) — decrypted `/data` view.
- `/dev/mapper/userdata-rw` (dm-1, read-write) — decrypted `/data` view.
- Snapshot: `/dev/mapper/userdata-snap` (dm-2) over origin `userdata-rw` + COW `/dev/loop0`.

---

## Step 4 — Verify decryption on host

- AES-256-XTS, sector size 4096, tweak = block index.
- f2fs magic `0xF2F52010` at block `0x400` and `0x1400`.
- dm mapping output == host decryption output (verified over 1 MiB).

---

## Step 5 — f2fs state findings

- f2fs superblock v1.13, `block_count=6532087` (~24.9 GiB).
- Checkpoint packs at blocks 512 and 1024; CRC uses raw kernel CRC32 with seed
  `F2FS_SUPER_MAGIC` (`0xF2F52010`).
- `CP_NAT_BITS_FLAG = 0x80`; checkpoint packs had `0x281` / `0x850`.
- NAT version bitmaps pointed at the empty second half; valid NAT entry for the root
  inode was in the first half.

A write made via `> /dev/mapper/userdata-snap` (no `seek`) corrupted the superblock; the
block was subsequently restored from a pristine decrypted block.

---

## Step 6 — Current status

- Key: **RECOVERED AND VERIFIED**.
- Decryption mapping: **VERIFIED**.
- Filesystem mount on the recovery kernel: **BLOCKED** (`Failed to read root inode`) — remaining
  work: run `fsck.f2fs` on a decrypted copy, or use a newer f2fs.
- Next: get the key + data out, then reset/flash and resume the GPU custom-kernel phase.

---

## Do not

- Do not wipe, factory reset, format `/data`, or wipe `/metadata`.
- Do not overwrite the images or publish the recovered key material.

---

## References

- `../recovery/README.md` — triage notes.
- `../recovery/analysis.md` — detailed findings.
- `../recovery/hashes.txt` — hashes.
- `../scripts/verify.sh` — read-only verification.
