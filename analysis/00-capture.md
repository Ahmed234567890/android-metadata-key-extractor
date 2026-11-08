# 00 — Stock capture (Phase 0)

Record of the first capture: what was taken off the device, how it was verified,
and what it established. Everything here was measured on 2026-11-01 against
build `A032FXXS9CZA2`.

## Method

Staged on the device as root into `/data/local/tmp/cap`, then pulled with
`adb pull`. Block devices cannot be pulled directly, so `boot` was copied with
`dd` first. Hashing was done on the host; nothing was written to the device.

Reproduce with `scripts/capture.sh`, then `scripts/verify.sh`.

## What was taken

| Source | Destination |
| --- | --- |
| `/dev/block/by-name/boot` (`mmcblk0p40`, 64 MiB) | `boot.img` |
| `/mnt/vendor/socko/*.ko` (20 modules) | `socko/` |
| `/vendor/lib/modules/*.ko` (12 modules) | `vendor-modules/` |
| `/proc/config.gz` | `kernel-config.gz` |
| `/proc/modules`, `lsmod`, `mount`, `/proc/cmdline` | `facts/` |
| `/sys/module/pvrsrvkm/parameters/*` | `facts/module-params.txt` |

## Integrity

The module that was pulled is the module that is running:

* Build ID in `pvrsrvkm.ko`: `ba3eed02545fe11c`
* Build ID in `/sys/module/pvrsrvkm/notes/.note.gnu.build-id`: `ba3eed02545fe11c`
* sha256: `6843bf0ee967ba623dc5038e1967f0769c083f18b6a0c5b91f4ddfdf19486d2c`

`boot.img` is exactly 67,108,864 bytes, the size reported by
`blockdev --getsize64` for `mmcblk0p40`, so the whole partition was read.

## Findings

### 1. The GPU module is on its own read-only ext4 partition

`init.md.rc` and `init.cali.rc` contain:

```
insmod ${ro.vendor.ko.mount.point}/socko/pvrsrvkm.ko
```

`ro.vendor.ko.mount.point` is `/mnt/vendor`, and `/mnt/vendor/socko` is
`/dev/block/mmcblk0p43`, ext4, mounted `ro` and **not** dm-verity protected.

Implication: extraction is a plain file copy, not a boot-image unpack, and the
module can be replaced on its own partition without touching `boot.img`. The
boot ramdisk is 938,585 bytes and contains no `.ko` files at all, which rules
out the ramdisk as the load path.

### 2. The module is AArch64, not ARM32

```
Class:   ELF64
Machine: AArch64
vermagic=4.14.199-27418755-abA032FXXS9CZA2 SMP preempt mod_unload modversions aarch64
```

Userspace on this device is `armeabi-v7a`, which is why every earlier phase of
this project was 32-bit. The kernel and its modules are 64-bit. Any patch must
be assembled for `aarch64`.

### 3. The licence is `Dual MIT/GPL`, and the source is not published

```
license=Dual MIT/GPL
author=Imagination Technologies Ltd. <gpl-support@imgtec.com>
```

The kernel taint for this module is `O` only:

```
$ cat /sys/module/pvrsrvkm/taint
O
```

There is no `P` (proprietary module) bit, and the global `/proc/sys/kernel/tainted`
is `4608` (bits 9 and 12), which likewise does not include bit 0. The module
therefore declared a GPL-compatible licence at build time, and the
corresponding source was never released. The address for a source request is in
the module itself.

Implication for this project: taking the module under its GPL arm gives a clean
basis for study and modification. It does not provide source — the analysis
still proceeds by reverse engineering.

### 4. Symbols are intact, DWARF is not

| | |
| --- | --- |
| `.symtab` | present, 3473 symbols |
| defined functions | 2283 |
| imported kernel symbols | 266 |
| `.debug_info`, `.debug_str` | absent |
| `.BTF` | absent |

The file is 2,954,344 bytes while `/sys/module/pvrsrvkm/coresize` is 1,261,568;
the difference is symbol and relocation tables, not debug information.

Implication: function names and boundaries are available, struct layouts are
not. Expect to recover types from the code and from the userspace DDK headers.

### 5. Signing is not enforced, unloading is possible but not live

```
# CONFIG_MODULE_SIG is not set
CONFIG_MODULE_UNLOAD=y
# CONFIG_MODULE_FORCE_UNLOAD is not set
CONFIG_MODVERSIONS=y
```

A modified module will load. `rmmod` is legal but cannot be forced, and the
refcount is ~900 while the UI is running, so the only reload window is boot,
before SurfaceFlinger starts. `modversions` means imported-symbol CRCs are
checked: in-place edits are safe, adding a new kernel-symbol import is not.

### 6. The vendor passes no module parameters

The `insmod` line has no arguments. Every parameter is a compiled-in default:

| Parameter | Default |
| --- | --- |
| `DisableClockGating` | `N` |
| `EnableFWContextSwitch` | `0x0000000f` |
| `EnablePageFaultDebug` | `Y` |
| `EnableRDPowerIsland` | `0x00000002` |
| `PVRDebugLevel` | `7` |
| `GeneralNon4KHeapPageSize` | `0x00004000` |

All of them are writable at runtime through sysfs, so they can be swept without
a reload. Only a change to a *boot default* requires a patch or a reload with
arguments.

### 7. Tracing is available without patching

`/sys/kernel/tracing/kprobe_events` exists and is writable, with
`CONFIG_KPROBES=y`, `CONFIG_KPROBE_EVENTS=y` and `CONFIG_KALLSYMS_ALL=y`.
`CONFIG_FUNCTION_TRACER` is off, so there is no `available_filter_functions`,
but kprobe events on symbol names work.

### 8. The GPU registers its own DRM render node

```
card0       sprd-drm-drv   /display-subsystem
card1       pvrsrvkm       /soc/mm/gpu@60000000
renderD128  pvrsrvkm       /soc/mm/gpu@60000000
```

`renderD128` is a PVR DRM node and is already bind-mounted into the Kali chroot.
At capture time 21 file descriptors were open on it. The claim in
`mesa-pvr-ge8322` that there is "no `/dev/dri`" is therefore wrong — it is a
userspace implementation gap, not a platform limitation. Correcting it is
Phase 3 work.

### 9. The module partition remounts read-write, so the restore path works

`/mnt/vendor/socko` is mounted `ro` by fstab but is a plain ext4 partition with
no dm-verity layer, and it accepts a remount:

```
mount -o remount,rw /mnt/vendor/socko   -> rw
touch /mnt/vendor/socko/.rwtest         -> OK
rm -f /mnt/vendor/socko/.rwtest
mount -o remount,ro /mnt/vendor/socko   -> ro
sha256sum pvrsrvkm.ko                   -> unchanged
```

The write test file was removed immediately; `pvrsrvkm.ko` was not touched and
its hash is identical before and after. This validates the restore procedure in
`scripts/restore.sh` and gives a second way to install a patched module, without
touching `boot.img` and without a Magisk overlay.

It is still the riskier of the two options, because a bad module written there
is what the system boots, with no fallback. The Magisk `post-fs-data` path keeps
the stock module on disk as the fallback, so that remains the default.

## What this changes

* Phase 0 is a file copy, not a boot-image surgery exercise.
* The module is AArch64; tooling must follow.
* Phase 1 (diagnostics) can start with kprobe events and needs no patched
  module at all.
* Phase 3 (dma-buf) has a real node to work against and needs no kernel change.
* A reload requires a boot-time window, which is what the Magisk `post-fs-data`
  path in `patches/README.md` is for.
