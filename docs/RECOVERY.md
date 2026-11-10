# Full recovery writeup — SM-A032F `/data` (public version)

**Target**: Samsung Galaxy A03 Core (`SM-A032F`, Unisoc SC9863A, board `m168`), user data on
`mmcblk0p55`, TEE metadata on `mmcblk0p45`.
**Scope**: recover photos, videos, Downloads, Aegis 2FA vault, kernel modules, Magisk modules from
the encrypted `/data` **without wiping the device**.

> **Public-release note**: this document describes the complete end-to-end recovery. All key
> material and key values are redacted/omitted; hashes and paths are public-safe. Nothing in this
> repository contains recovered key bytes.

---

## 1. Executive summary

| Question | Answer |
| --- | --- |
| Was `/data` wiped? | **No.** Never wiped, formatted or reset. |
| Was `/metadata` touched? | **No.** Read-only. |
| Were original images modified? | **No.** All work on copies. |
| Could the data be decrypted offline? | **Yes** — TEE-unwrapped metadata key → fscrypt v2 keys → AES-256-XTS. |
| Were all payloads recovered? | **Practically yes** — final device-vs-local comparison: **0 missing**, **0 unreadable**. |
| Known content-level gaps | 2 (truncated MP4; one boomerang capture) — documented. |

Deliverable payload trees on the analysis host:

```
/home/ahmed/recovered/media      ~1.9 GiB   (4502 files)   photos, videos, downloads, …
/home/ahmed/recovered/adb        ~12 MiB   (Magisk db + modules)
/home/ahmed/recovered/aegis      Aegis 2FA vault (sqlite OK)
/home/ahmed/recovered/local_tmp  misc local payloads
/home/ahmed/recovered2/          offline-extract staging
```

## 2. Phase timeline (repo commits)

```
19ceb55 Phase 0: stock capture of SM-A032F boot image and kernel modules
603de4d Phase 0: verify the restore path against the live partition
60b8ef7 scripts/verify.sh: take exactly the 8-byte build id
fc22692 Phase 1: zero-patch tracing of pvrsrvkm
acb58de Phase 0: read-only triage of /data and /metadata (TEE-bound key, correct boot stack)
f4e738c Phase 3: stability harness for pvrsrvkm
a454ca0 Phase 2: mountfix checkpoint redirect and read-only hold path
9437e42 recovery: USB serial rescue console instead of early-fs adbd
71a812b Phase 4: offline fscrypt extraction of /data media, adb, and Aegis vault
b9c1d55 Phase 5: full documentation of the SM-A032F /data recovery - every step, method, parameter and result
```

## 3. Working methods

### 3.1 Images (read-only originals; hashes in `recovery/hashes.txt`)

- `userdata.img` 26,755,444,828 B — `/data` (`mmcblk0p55`), dm-default-key ciphertext.
- `metadata.img` 16,777,298 B — `/metadata` (`mmcblk0p45`), TEE-wrapped key files.
- `misc_p8_backup.img` 1,048,576 B, `boot_p40_backup.img`, `bootchk/boot_unrooted.img`.

### 3.2 Decryption mathematics (documented, key redacted)

- Master key: 64 bytes, unwrapped via Trusty keymaster TA over TIPC.
- Contents key: `PRK = HMAC-SHA512(64 zero bytes, master)` → HKDF → AES-256 key (fscrypt v2).
- Content cipher: AES-256-XTS, tweak = `le64(ino<<32) + lblk`, sector 4096.
- Filename cipher: AES-CBC, IV = `le64(ino<<32) + zeros`, after CS3 swap of last two 16-byte blocks.

### 3.3 Offline fscrypt/f2fs extraction (`tools/f2fs_recover.py`)

- Metadata (NAT, inodes, dentries) from decrypted snapshot `userdata_dec.img`.
- NAT overlay from `userdata_nat_patched.img` (base block 2560, stride 455, block stride 512).
- Logical block map: direct + IND1/IND2/DIND via NAT journal resolution with main-area bounds checks.
- XTS-decrypt full 4096-byte blocks, truncate to `i_size`.

### 3.4 Rescue/patch (device side)

- cp2 checkpoint bitmap redirect → patched copy `/home/ahmed/cp2_patched.bin`.
- Device-mounted read-only via dm-0 at `/mnt/recdata` after mountfix; never rw.

## 4. Results detail

- Offline full extract: `/data/media/0` → 4390 files; `/data/adb` → 826 files.
- Instagram: 87 photos via stale inode walk.
- Missing-file recovery: 21 recovered via f2fs node-footer scan; boomerang capture not recoverable.
- Final comparison: media — device 4384 / local 4502, **missing 0**, **unreadable 0**, size mismatches 2;
  adb — device 527 / local 1215, **missing 0**, size mismatches 0.

### 4.1 Known gaps

1. `Movies/Instagram/VID_20260730_085244_293.mp4` — truncated (7,708,672 B recovered vs 14,986,458 B
   device size); ftyp magic valid; block-map resolution incomplete (needed 3659 logical blocks,
   resolved 1883 after indirect-block fix).
2. `boomerang_frame_capture` (ino 407440) — only directory-mode candidates → unrecovered.

## 5. Public release contents

See [`README.md`](README.md) for the public overview and quick start; [`docs/KEY_RECOVERY.md`](KEY_RECOVERY.md)
for the key procedure; [`src/`](src/) and [`tools/`](tools/) for code.

## 6. Do not

- Do not wipe, factory reset, format `/data`, or wipe `/metadata`.
- Do not publish recovered key material; this repository does not contain it.

---

*Public release. No key material, plaintext keys or secrets are included. Recovery images and key
files are git-ignored (`recovery/keys/`, `*.bin`, `*.img`).*
