# android-metadata-key-extractor — SM-A032F metadata key recovery

Private archive of the **Android metadata key recovery** for the Samsung Galaxy A03 Core
(`SM-A032F`, Unisoc SC9863A, board `m168`) — the key that encrypts `/data` via Android
metadata encryption (`dm-default-key` + TEE-wrapped key, TrustKernel).

The key was recovered through the device's own Trusty keymaster TA over TIPC and verified
against the encrypted userdata image. This repository documents the recovery procedure,
the tooling and the verification evidence.

**This repository is private on purpose.** It contains recovery documentation and scripts.
The recovered key material itself (`recovery/keys/`) is deliberately **not** published here.

## Device identity

| Property | Value |
| --- | --- |
| Model | SM-A032F (Galaxy A03 Core) |
| SoC | Spreadtrum/Unisoc SC9863A (`sp9863a`, board `m168`, PHY `sharkl3`) |
| GPU | PowerVR Rogue GE8322, BVNC 22.86.104.218, DDK 1.18@6267915 |
| Kernel | `4.14.199 … armv8l` (recovery, LineageOS 11); userspace `armeabi-v7a` |
| Build | `AP2A.240905.003`, `A032FXXS9CZA2`, `user/test-keys`, 2026-01-09 |

## What was recovered

| Item | Status |
| --- | --- |
| TEE-wrapped key files (`keymaster_key_blob`, `encrypted_key`, `secdiscardable`, `version`) | intact in `/metadata` (`metadata.img`) |
| 64-byte metadata key (via TIPC keymaster `Begin/Update/Finish`) | **RECOVERED** |
| Decryption mapping via `dm-default-key` (`aes-xts-plain64`) | **VERIFIED** (dm output == host AES-256-XTS) |
| f2fs superblock / checkpoint state | decoded and verified (`fsck.f2fs` build in progress) |

## How the key was recovered — step by step

Full step-by-step procedure: [`docs/KEY_RECOVERY.md`](docs/KEY_RECOVERY.md)

1. Capture `/data` (`mmcblk0p55`) and `/metadata` (`mmcblk0p45`) images (read-only).
2. Pull TEE key files from `/metadata`.
3. Talk to the Trusty keymaster TA over TIPC (`com.android.trusty.keymaster`).
4. `UPGRADE_KEY` → `BEGIN` → `UPDATE` → `FINISH`; `UPDATE` returned the 64-byte key,
   `FINISH` verified the GCM tag.
5. Load `dm-default-key` mapping over the userdata device.
6. Verify: host AES-256-XTS (4096-byte sectors, tweak = block index) == dm mapping output.

## Contents

| Path | What |
| --- | --- |
| `docs/KEY_RECOVERY.md` | Step-by-step key recovery procedure. |
| `recovery/` | Read-only triage, analysis, hashes, verify script. |
| `scripts/` | Capture / restore / trace / stability / verify scripts. |
| `analysis/` | Capture findings, symbol maps, trace pipeline, phase-2 traces. |
| `device/` | Device facts, kernel config, module listings. |
| `MANIFEST.sha256`, `RELEASE.sha256` | Artifact hashes. |

## Current status

- **Metadata key: RECOVERED AND VERIFIED.**
- **Decryption mapping: VERIFIED.**
- **Filesystem mount: BLOCKED** on the recovery kernel (`Failed to read root inode`) — next step is
  to run `fsck.f2fs` on a decrypted copy, or use a newer f2fs.
- **Next**: extract `/data` content, then reset/flash and resume the GPU custom-kernel phase.

## Do not

- Do not wipe, factory reset, format `/data`, or wipe `/metadata`.
- Do not overwrite the images or publish the recovered key material.

## References

- Original archive: <https://github.com/Ahmed234567890/proprietary-stuff>
