# 02 — Zero-patch tracing of `pvrsrvkm`

Phase 1 instrumented the running module without changing a byte of it. This
file records how the tracing works, what the probes mean, and what the first
three captures show.

## Why there is no patch

Phase 0 found `CONFIG_KPROBES=y`, `CONFIG_KPROBE_EVENTS=y` and
`CONFIG_KALLSYMS_ALL=y` on this kernel, so function-entry probes can be
attached to any symbol in the module at runtime. `CONFIG_FUNCTION_TRACER` is
off, so there is no `available_filter_functions`, but kprobe events do not need
it.

Consequence: `patches/` is still empty. Nothing in this phase required a
modified module, a reboot, or a change to `/mnt/vendor/socko`.

## How to run it

```sh
./scripts/trace.sh list               # can every probe be registered?
./scripts/trace.sh run gles 3         # 3 s around the GLES smoke test
./scripts/trace.sh run vulkan 3
./scripts/trace.sh run vaapi 5
./scripts/trace.sh run idle 10
```

The trace goes to stdout, diagnostics to stderr, so `> raw/trace-gles.txt`
keeps the two apart. The device side is a script piped over stdin
(`adb shell 'su -c "sh -s"'`), which avoids the quoting problems of nested
`su -c` strings.

Properties of the harness:

* **Nothing leaks.** A `trap cleanup EXIT` on the device clears
  `events/enable` and `kprobe_events` even when the workload fails.
* **Only probe lines are returned.** `grep -E ': (pvropen|...):'` filters the
  buffer; `trace_marker` traffic from `atrace` would otherwise flood it.
* **Buffer** is set to 16 MiB and `tracing_on` is 0 while probes are
  registered, so no events are lost during setup. No drops were observed.
* **The offset probe is gated.** `pvrhandler` attaches at
  `BridgedDispatchKM+0x470`, which is only the handler load in *this* build.
  The script reads `/sys/module/pvrsrvkm/notes/.note.gnu.build-id` and skips
  the probe unless it is `ba3eed02545fe11c`.
* **Handler names are resolved on the host.** `kptr_restrict` is 2 on this
  device, so root has to drop it to 0 to read `/proc/kallsyms`. `trace.sh`
  does that for the duration of one read and restores the previous value.
  Resolution uses `python3` on the host; without it the raw `handler=0x...`
  addresses are still printed.

## The probes

| Probe | Attach point | Fetch args | What it records |
| --- | --- | --- | --- |
| `pvropen` | `pvr_drm_open` | — | a process opened `/dev/dri/renderD128` or `card1` |
| `pvrrelease` | `pvr_drm_release` | — | that fd was closed |
| `pvrdispatch` | `BridgedDispatchKM` entry | `+0(%x1):u32` | bridge group of every ioctl |
| `pvrhandler` | `BridgedDispatchKM+0x470` | `%x8`, `+0(%x19)`, `+4(%x19)` | the exact handler, group and function index |
| `mmufault` | `MMU_CheckFaultAddress` | `%x1` | device virtual address of a GPU fault |
| `rgxfault` | `RGXCheckFaultAddress` | — | firmware-reported fault |
| `devmemfault` | `DevmemIntGetFaultAddress` | — | fault address read-back |
| `rgxpoweroff` | `RGXPrePowerState` | — | RGX core powering down |
| `rgxpoweron` | `RGXPostPowerState` | — | RGX core powering up |
| `idlereq` | `PVRSRVDeviceIdleRequestKM` | — | driver asked for idle |
| `idlecancel` | `PVRSRVDeviceIdleCancelRequestKM` | — | idle request cancelled |
| `clockpre` | `RGXPreClockSpeedChange` | — | DVFS stepping down |
| `clockpost` | `RGXPostClockSpeedChange` | — | DVFS stepping up |

`pvrdispatch` and `pvrhandler` both fire once per ioctl, so a call shows up as
two lines. The tables below count `pvrhandler` only.

## Decoding the bridge packet

`BridgedDispatchKM(psDeviceNode, psPacket)` receives the packet in `x1`
(saved to `x19`). The disassembly of the stock module shows:

```
3cf70: ldr  w5, [x19]            ; w5 = packet[0]
3cf78: cmp  w5, #0x8c            ; must be < 140 (the group count)
3cfdc: add  x8, x8, w9, uxtw #2  ; x8 = group_table + group*4
3cfe4: ldrh w5, [x8]             ; u16 base
3cfe8: ldrh w6, [x8, #2]         ; u16 limit
3cff0: ldr  w8, [x19, #4]        ; w8 = packet[1]
3cff4: add  w23, w8, w5          ; index = packet[1] + base
3cff8: cmp  w23, w6              ; must be <= limit
```

So the first word is a **bridge group** and the second word is a **function
index inside that group**. The group table (`g_BridgeDispatchTableStartOffsets`,
140 entries of two `u16`) is filled at module init, which is why it is not
readable from the `.ko` file.

The dispatch index then selects a 24-byte entry of `g_BridgeDispatchTable`
(175 entries, `4200 / 24`):

```
3d38c: mov  w8, #24
3d390: mul  x8, x28, x8
3d394: ldr  x8, [x27, x8]        ; x8 = table[index].pfn
3d398: cbz  x8, ...
3d3b0: blr  x8                   ; call the handler
```

Probing at `+0x470` (the `cbz`) therefore yields `x8` = the handler address.
`/proc/kallsyms` names it, which is how the traces below turn raw numbers into
`PVRSRVBridgeDevmemIntMapPMR2` and friends. No DDK header is needed.

The group numbers are named from the handlers observed in them, not from a
header: 1 = core/device, 2 = sync, 6 = MM (PMR, devmem, heaps), 13 = cache,
19 = devicemem history, 128 = RGX transfer queue, 130 = RGX TA3D.

## Evidence

Three captures, all on the stock module in one boot. Raw files are in
[`traces/`](traces/).

### Event counts

| Capture | Bridge calls | Power off | Power on | Open | Release | Faults |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `gles` (3 s) | 382 | 6 | 6 | 1 | 1 | 0 |
| `vulkan` (3 s) | 28 | 4 | 4 | 2 | 2 | 0 |
| `idle` (10 s) | 60 | 24 | 24 | 0 | 0 | 0 |

### Commands seen

`group`/`fn` are the two packet words, `handler` is what the kernel actually
called.

| group | fn | handler | GLES | Vulkan | idle 10 s |
| ---: | ---: | --- | ---: | ---: | ---: |
| 1 | 0 | `PVRSRVBridgeConnect` | 1 | 1 | 0 |
| 1 | 1 | `PVRSRVBridgeDisconnect` | 0 | 1 | 0 |
| 1 | 2 | `PVRSRVBridgeAcquireGlobalEventObject` | 1 | 1 | 0 |
| 1 | 3 | `PVRSRVBridgeReleaseGlobalEventObject` | 0 | 1 | 0 |
| 1 | 4 | `PVRSRVBridgeEventObjectOpen` | 12 | 0 | 0 |
| 1 | 5 | `PVRSRVBridgeEventObjectWait` | 2 | 0 | 0 |
| 1 | 6 | `PVRSRVBridgeEventObjectClose` | 9 | 0 | 0 |
| 1 | 10 | `PVRSRVBridgeAlignmentCheck` | 1 | 1 | 0 |
| 1 | 15 | `PVRSRVBridgeAcquireInfoPage` | 1 | 1 | 0 |
| 1 | 16 | `PVRSRVBridgeReleaseInfoPage` | 0 | 1 | 0 |
| 2 | 0 | `PVRSRVBridgeAllocSyncPrimitiveBlock` | 2 | 0 | 0 |
| 2 | 2 | `PVRSRVBridgeSyncPrimSet` | 3 | 0 | 0 |
| 2 | 7 | `PVRSRVBridgeSyncAllocEvent` | 3 | 0 | 0 |
| 6 | 3 | `PVRSRVBridgePMRMakeLocalImportHandle` | 4 | 0 | 0 |
| 6 | 4 | `PVRSRVBridgePMRUnmakeLocalImportHandle` | 4 | 0 | 0 |
| 6 | 6 | `PVRSRVBridgePMRLocalImportPMR` | 5 | 1 | 0 |
| 6 | 7 | `PVRSRVBridgePMRUnrefPMR` | 21 | 3 | 0 |
| 6 | 9 | `PVRSRVBridgePhysmemNewRamBackedPMR` | 43 | 0 | 0 |
| 6 | 15 | `PVRSRVBridgeDevmemIntCtxCreate` | 1 | 0 | 0 |
| 6 | 17 | `PVRSRVBridgeDevmemIntHeapCreate` | 11 | 0 | 0 |
| 6 | 30 | `PVRSRVBridgeHeapCfgHeapCount` | 1 | 0 | 0 |
| 6 | 32 | `PVRSRVBridgeHeapCfgHeapDetails` | 11 | 0 | 0 |
| 6 | 35 | `PVRSRVBridgePhysHeapGetMemInfo` | 0 | 1 | 0 |
| 6 | 44 | `PVRSRVBridgeChangeSparseMem2` | 2 | 0 | 0 |
| 6 | 45 | `PVRSRVBridgeDevmemIntReserveRange2` | 44 | 0 | 0 |
| 6 | 46 | `PVRSRVBridgeDevmemIntUnreserveRange2` | 21 | 2 | 0 |
| 6 | 47 | `PVRSRVBridgeDevmemIntMapPMR2` | 44 | 0 | 0 |
| 6 | 48 | `PVRSRVBridgeDevmemIntUnmapPMR2` | 21 | 2 | 0 |
| 13 | 0 | `PVRSRVBridgeCacheOpQueue` | 1 | 0 | 0 |
| 19 | 0 | `PVRSRVBridgeDevicememHistoryMap` | 59 | 0 | 0 |
| 19 | 1 | `PVRSRVBridgeDevicememHistoryUnmap` | 34 | 2 | 0 |
| 19 | 4 | `PVRSRVBridgeDevicememHistorySparseChange` | 2 | 0 | 0 |
| 128 | 0 | `PVRSRVBridgeRGXCreateTransferContext` | 1 | 0 | 0 |
| 128 | 3 | `PVRSRVBridgeRGXSubmitTransfer2` | 1 | 0 | 0 |
| 130 | 8 | `PVRSRVBridgeRGXCreateRenderContext` | 1 | 0 | 0 |
| 130 | 9 | `PVRSRVBridgeRGXDestroyRenderContext` | 1 | 0 | 0 |
| 130 | 12 | `PVRSRVBridgeRGXKickTA3D2` | 11 | 10 | 60 |
| 130 | 15 | `PVRSRVBridgeRGXCreateFreeList2` | 2 | 0 | 0 |
| 130 | 16 | `PVRSRVBridgeRGXCreateHWRTDataSet2` | 1 | 0 | 0 |

By group, the GLES run is 233 MM (61.0%), 95 devicemem history (24.9%), 27
core/device (7.1%), 16 RGX TA3D (4.2%), 8 sync (2.1%), 2 RGX transfer and 1
cache.

## Findings

### 1. A trivial GLES workload is dominated by memory setup, not drawing

382 bridge calls for one `egl-gles2-smoke`, of which 11 are
`RGXKickTA3D2` — 2.9%. The other 97% is buffer and address-space management:
PMR creation, range reservation, mapping, unmapping and reference dropping.

This matters for later phases: a per-app workaround is the wrong unit of
change, because the expensive path is shared setup. It also means that a
change to the mapping path is measurable at a 61% share of traffic.

### 2. Devicemem history is enabled and costs a quarter of the calls

`PVRSRVBridgeDevicememHistoryMap` (59) and `...Unmap` (34) plus two
`SparseChange` are 95 of 382 calls, for a smoke test that draws a few frames.
This is a debug/tracking feature, and it is the second-largest source of
bridge traffic while doing nothing useful for rendering.

It is a concrete target for Phase 2/5: the module has a
`DEVICEMEMHISTORY` bridge, and the traffic is large enough that disabling it
would be visible in the same measurement.

### 3. The GPU is power-cycled about once per second per caller, even when idle

In the 10-second idle capture there are 24 power-down events, in a strict
pattern: one from `RenderThread` and, 29 ms later, one from a `kworker`. Each
`RGXPrePowerState` is followed by `RGXPostPowerState` about 20 µs later, so
these are full off/on pairs, not failed power-downs:

```
RenderThread  19297.458870  rgxpoweroff
RenderThread  19297.459958  rgxpoweron
kworker/u16:0 19297.480006  rgxpoweroff
kworker/u16:0 19297.480230  rgxpoweron
RenderThread  19298.469922  rgxpoweroff
...
```

Intervals alternate between ~29 ms and ~0.97 s, i.e. two independent callers
each cycling at ~1 Hz. The same cadence appears during the GLES run (6 pairs
in 3 s).

This is the main stability lead for Phase 2: the core is not staying powered
between frames, and every cycle re-runs the power-up path. It is also a power
cost on a device whose idle state is never actually idle.

### 4. No page faults, in any capture

`MMU_CheckFaultAddress`, `RGXCheckFaultAddress` and
`DevmemIntGetFaultAddress` never fired. That is a clean baseline, and it also
means the fault probes are wired but **not yet validated against a real
fault**. Validating them needs a deliberate fault (Phase 2), not more workload
runs.

### 5. The idle-request and DVFS probes never fired

`PVRSRVDeviceIdleRequestKM`, `PVRSRVDeviceIdleCancelRequestKM`,
`RGXPreClockSpeedChange` and `RGXPostClockSpeedChange` produced nothing. The
power transitions above do not pass through the idle-request API, and DVFS did
not step during any capture. Whatever drives the 1 Hz cycling is upstream of
those symbols.

### 6. Vulkan opens the render node twice

The `vulkaninfo` run shows two `pvr_drm_open`/`pvr_drm_release` pairs and a
`Connect`/`Disconnect` pair, with 10 `RGXKickTA3D2` calls. The GLES path opens
once. This is expected for a Vulkan loader that enumerates physical devices,
but it is worth remembering when comparing per-process fd lifetimes.

## Limitations

* The `pvrhandler` offset is pinned to build `ba3eed02545fe11c`. On any other
  module the probe is skipped rather than attached at a possibly wrong
  instruction.
* Handler resolution needs `/proc/kallsyms` with `kptr_restrict=0`; the script
  restores the original value. Addresses are per-boot and are not portable.
* `idle` is not a quiesced GPU: SurfaceFlinger still submits 60 kicks in 10 s.
  With the screen off, the same capture yields zero bridge calls, which is a
  different state and is why the device state is recorded with the traces.
* Fault probes are untested against a fault.
* `vaapi` is implemented in the harness but was not captured in this phase;
  the decode path is Phase 3/4 work and needs the test stream staged first.

## Reproduce

```sh
SERIAL=192.168.1.16:43577 ./scripts/trace.sh run gles 3   > raw/trace-gles.txt
SERIAL=192.168.1.16:43577 ./scripts/trace.sh run vulkan 3 > raw/trace-vulkan.txt
SERIAL=192.168.1.16:43577 ./scripts/trace.sh run idle 10  > raw/trace-idle.txt
```

Wake the device first (`input keyevent 26`), otherwise the idle capture is
empty. Serial numbers change on this device; get the current one from
`adb devices`.
