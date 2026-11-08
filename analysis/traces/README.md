# Trace evidence

Raw kprobe captures produced by `scripts/trace.sh`, kept here so the tables in
[`02-trace-pipeline.md`](../02-trace-pipeline.md) can be checked without a
device.

| File | Workload | Duration | Device state |
| --- | --- | --- | --- |
| `trace-gles.txt` | `run-x11-gles egl-gles2-smoke` | ~3 s | screen on, awake |
| `trace-vulkan.txt` | `vulkaninfo --summary` | ~3 s | screen on, awake |
| `trace-idle.txt` | no workload (`sleep 10`) | 10 s | screen on, awake |

All three were captured in one boot of the stock module:

```
boot_id      194b65c3-ed2f-47b0-8403-56588fdd9d55
module       pvrsrvkm.ko, build id ba3eed02545fe11c
text base    0xffffffb88226af24
```

Handler addresses in the traces have already been resolved to symbol names
against `/proc/kallsyms` from that boot; the raw addresses are not portable
because the module base changes on every boot.

Line format is the tracefs one:

```
<comm>-<pid> [<cpu>] <flags> <seconds>: <probe>: (<symbol>+<off>/<size> [pvrsrvkm]) <fields>
```

Regenerate with:

```sh
./scripts/trace.sh run gles 3    > raw/trace-gles.txt
./scripts/trace.sh run vulkan 3  > raw/trace-vulkan.txt
./scripts/trace.sh run idle 10   > raw/trace-idle.txt
```

The device must be awake. With the screen off the compositor stops submitting
work and the idle baseline collapses from 60 bridge calls to zero; that is a
real state difference, not a tracing failure.
