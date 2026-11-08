# SM-A032F `/data` recovery (non-destructive)

Status: **data intact, encrypted, not yet recovered.** Offline decryption from
the extracted images is **not possible** — the metadata key is wrapped by the
phone's TrustKernel TEE, and only the phone can unwrap it.

This directory records the read-only triage of the images extracted from the
device after it dropped to recovery with `init_user0_failed`. Nothing here
writes to the images.

## Bottom line

| Question | Answer |
| --- | --- |
| Is the data still there? | Yes. `userdata.img` is the full 24.9 GiB `/data` partition. |
| Can it be decrypted on a PC? | No. `/data` uses Android metadata encryption (`dm-default-key`); the 64-byte key is encrypted with a TEE key (`pKMblob`, TrustKernel). |
| Is the key still valid? | Yes. Key files are dated 18 Jul 2026 (setup date) and survive journal replay unchanged. |
| Was the wrong boot image flashed? | No. The unrooted image is the same build as the original (same `init`, kernel, DTB, and fstab). |
| What probably failed? | `/data` f2fs corruption after the bootloop and repeated hard reboots, or a keymaster/TEE failure. The normal-boot log was overwritten, so the exact cause is not yet captured. |
| What to do? | Get the phone back, boot it (same build), capture the normal-boot log, then run `fsck.f2fs` on the decrypted device via TWRP or a custom initramfs. Do **not** wipe. |

## Images (read-only)

| File | Size | What it is |
| --- | --- | --- |
| `userdata.img` | 26,755,444,828 B | full `/data` (`mmcblk0p55`), dm-default-key ciphertext |
| `userdata.trim.img` | 26,755,444,736 B | same, trimmed to the exact partition size |
| `userdata_encrypted.img` | 10,402,595,840 B | earlier/partial dump; matches `userdata.img` for the first 4,472,589,825 B, then diverges |
| `metadata.img` | 16,777,298 B | `/metadata` ext4, holds the TEE-wrapped key |
| `metadata.trim.img` | 16,777,216 B | same, exact partition size |
| `misc_p8_backup.img` | 1,048,576 B | `/misc`; BCB says `--prompt_and_wipe_data --reason=init_user0_failed` |
| `boot_p40_backup.img` | 67,108,864 B | original boot, Magisk-patched (`0727cd39…`) |
| `bootchk/boot_unrooted.img` | 67,108,864 B | unrooted boot the user flashed (`129308ed…`) |

Full hashes are in [`hashes.txt`](hashes.txt).

## Do not

- Do not wipe, factory reset, format `/data`, or wipe `/metadata`.
- Do not flash Samsung stock firmware/CSC over this LineageOS build.
- Do not overwrite `userdata.img`, `metadata.img`, or `misc_p8_backup.img`.
- Do not run `fsck` or any write operation on the images; work on copies.

## Documents

- [`analysis.md`](analysis.md) — detailed findings and evidence.
- [`verify.sh`](verify.sh) — read-only re-check of the images.
