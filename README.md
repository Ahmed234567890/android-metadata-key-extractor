# android-metadata-key-extractor

**Recover the Android userdata encryption key and decrypt `/data` — without wiping the device.**

This repository documents and implements an **end-to-end, authorized data-recovery procedure**
for Android devices using filesystem encryption (`dm-default-key` + TEE-wrapped metadata key,
i.e. Android 10+ FBE / 11+ fscrypt with the `direct` key scheme).

For the **Samsung Galaxy A03 Core (`SM-A032F`, Unisoc SC9863A, board `m168`)**, the procedure was
used to:

1. capture the encrypted `/data` and `/metadata` images (read-only),
2. pull the TEE-wrapped key blobs from `/metadata`,
3. unwrap the **64-byte filesystem encryption key** through the device's own
   **Trusty keymaster Trusted Application (TA) over TIPC**,
4. install the result as a **`dm-default-key` mapping** over the userdata device,
5. **verify** the mapping against host-side AES-256-XTS decryption,
6. **decrypt and extract** the full payload (photos, videos, Downloads, Aegis vault, Magisk
   modules, …) from the filesystem image offline.

The recovered key material itself is **never published** in this repository. Only
documentation, procedures, source code and hashes are public.

> **Authorized-use notice.** Recovery tooling like this must only be used on devices you own or
> have explicit permission to test. The techniques target local, offline, read-only recovery
> flows on your own hardware.

## Status

| Item | Status |
| --- | --- |
| TEE-wrapped key files (`keymaster_key_blob`, `encrypted_key`, `secdiscardable`, `version`) | intact in `/metadata` |
| 64-byte metadata key via TIPC keymaster (`UPGRADE_KEY`/`BEGIN`/`UPDATE`/`FINISH`) | **RECOVERED** (via device TEE) |
| `dm-default-key` mapping (`aes-xts-plain64`) | **VERIFIED** (dm output == host AES-256-XTS) |
| Full `/data` content extraction (offline fscrypt/f2fs) | **COMPLETE** (0 missing vs device manifest) |
| Known content-level gaps | 2 (see [docs/RECOVERY.md](docs/RECOVERY.md)) |

## How it works

```
/metadata (TEE-wrapped key blobs)
        │  TIPC ──▶ Trusty keymaster TA (com.android.trusty.keymaster)
        │          GET_VERSION → CONFIGURE → UPGRADE_KEY → BEGIN → UPDATE → FINISH
        ▼
    64-byte filesystem encryption key (AES-256-XTS, fscrypt v2)
        │  install as dm-default-key over /data
        ▼
/dev/mapper/userdata-dec  (dm-0, decrypted /data view, read-only)
        │  AES-256-XTS (4 KiB sectors, tweak = block index)
        │  + fscrypt v2 HKDF (PRK = HMAC-SHA512(64 zeros, master), CE/SP/DE keys)
        │  + filename cipher (CS3 + AES-CBC, IV = le64(ino<<32) + 0)
        ▼
offline f2fs parse → payload extraction
```

## Repository layout

| Path | What |
| --- | --- |
| [`docs/KEY_RECOVERY.md`](docs/KEY_RECOVERY.md) | Step-by-step metadata-key recovery procedure (public version, key redacted). |
| [`docs/RECOVERY.md`](docs/RECOVERY.md) | Full end-to-end recovery writeup: phases, methods, results, known gaps, deliverables. |
| [`src/`](src/) | Static ARM32 userspace source code used for the recovery. |
| [`tools/`](tools/) | Offline fscrypt/f2fs decryption and extraction implementation. |
| [`recovery/`](recovery/) | Read-only triage, analysis, hashes, verify script. |
| [`scripts/`](scripts/) | Capture / restore / trace / stability / verify helper scripts. |
| [`analysis/`](analysis/) | Capture findings, symbol maps, trace pipeline, traces. |
| [`device/`](device/) | Device facts, kernel config, module listings. |
| [`MANIFEST.sha256`](MANIFEST.sha256) / [`RELEASE.sha256`](RELEASE.sha256) | Artifact hashes. |

## Quick start

### Prerequisites

- Linux host (x86_64) with root/capabilities for device-mapper access.
- ARM32 cross toolchain (e.g. `clang --target=armv7a-linux-gnueabi`, `-nostdlib -static`).
- Python 3 with `cryptography` (`pip install cryptography`) for fscrypt v2 key derivation.
- Optional: `fsck.f2fs` / debugfs for offline filesystem inspection.

### Build the static ARM32 tools

```sh
# TIPC keymaster client (TEE key unwrap / DECRYPT operation)
PATH=/usr/lib/llvm22/bin:$PATH clang --target=armv7a-linux-gnueabi \
  -nostdlib -static -O2 -ffreestanding -fno-builtin -fno-stack-protector \
  -fuse-ld=lld -o kmclient kmclient_de.c

# fscrypt key install/verify tools (ARM32, static, freestanding)
clang --target=armv7a-linux-gnueabi -nostdlib -static -O2 -ffreestanding \
  -fno-builtin -fno-stack-protector -fuse-ld=lld -o fscrypt_id fscrypt_id.c
clang --target=armv7a-linux-gnueabi -nostdlib -static -O2 -ffreestanding \
  -fno-builtin -fno-stack-protector -fuse-ld=lld -o fscrypt_ce fscrypt_ce.c

# minimal dm table loader (dm-default-key table creation)
clang --target=armv7a-linux-gnueabi -nostdlib -static -O2 -ffreestanding \
  -fno-builtin -fno-stack-protector -fuse-ld=lld -o dmkey dmkey.c
```

### Use

```sh
# 1) Unwrap the 64-byte key through the TEE (procedure: docs/KEY_RECOVERY.md)
./kmclient ...

# 2) Create the dm-default-key mapping over the userdata device
./dmkey create userdata-dec ro default-key aes-xts-plain64 <KEY_HEX> 0 /dev/block/mmcblk0p55 0 2 sector_size:4096 iv_large_sectors

# 3) Verify (dm mapping output == host AES-256-XTS)

# 4) Decrypt content keys and extract files (tools/f2fs_recover.py)
python3 tools/f2fs_recover.py ...
```

## Verification summary

- Known-good anchors: file inode decrypt hashes matched (photo inode, ELF inode).
- dm mapping output == host AES-256-XTS decryption (1 MiB sample verified).
- Full-tree device-manifest comparison after merge: **0 missing**, **0 unreadable**.

## Do not

- Do not wipe, factory reset, format `/data`, or wipe `/metadata`.
- Do not overwrite recovery images; work on copies.
- Do not publish recovered key material; this repository does not contain it.

## References

- [`docs/KEY_RECOVERY.md`](docs/KEY_RECOVERY.md) — key recovery procedure.
- [`docs/RECOVERY.md`](docs/RECOVERY.md) — full recovery writeup.
- [`recovery/README.md`](recovery/README.md) — triage notes.
- [`recovery/analysis.md`](recovery/analysis.md) — detailed findings.
- [`recovery/hashes.txt`](recovery/hashes.txt) — image hashes.
- [`recovery/verify.sh`](recovery/verify.sh) — read-only verification.
