#!/bin/sh
# Attach kprobe events to pvrsrvkm and capture a trace around a workload.
#
#   ./scripts/trace.sh list              # which probes can be created
#   ./scripts/trace.sh run gles 3        # 3 seconds around the GLES smoke test
#   ./scripts/trace.sh run vulkan 3
#   ./scripts/trace.sh run vaapi 5
#   ./scripts/trace.sh run idle 10
#
# The trace goes to stdout, so redirect it:
#   ./scripts/trace.sh run gles 3 > raw/trace-gles.txt
#
# Nothing is patched: this uses CONFIG_KPROBE_EVENTS only. Probes are removed
# when the script exits, including on failure, by a trap on the device side.
set -eu

SERIAL=${SERIAL:-}
ADB="adb ${SERIAL:+-s $SERIAL}"
CH=${CH:-/data/local/nhsystem/kali-armhf}
T=/sys/kernel/tracing

# name symbol [fetch args]
#
# BridgedDispatchKM's second argument (x1) points at the bridge packet:
#   +0  bridge group id      (range-checked against 0x8c)
#   +4  function index in that group
# The real handler is loaded at BridgedDispatchKM+0x470 into x8 just before
# the indirect call, so probing there names the command exactly. That offset
# is only valid for the stock module (build id ba3eed02545fe11c), so the
# probe is registered only when the running module reports that build id.
# MMU_CheckFaultAddress takes the faulting device virtual address in x1.
PROBES='
pvropen      pvr_drm_open
pvrrelease   pvr_drm_release
pvrdispatch  BridgedDispatchKM          cmd=+0(%x1):u32
pvrhandler   BridgedDispatchKM+0x470    handler=%x8 cmd=+0(%x19):u32 fn=+4(%x19):u32
mmufault     MMU_CheckFaultAddress      addr=%x1
rgxfault     RGXCheckFaultAddress
devmemfault  DevmemIntGetFaultAddress
rgxpoweron   RGXPostPowerState
rgxpoweroff  RGXPrePowerState
idlereq      PVRSRVDeviceIdleRequestKM
idlecancel   PVRSRVDeviceIdleCancelRequestKM
clockpre     RGXPreClockSpeedChange
clockpost    RGXPostClockSpeedChange
'

PINNED_BUILD_ID=ba3eed02545fe11c

usage() {
    sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
}

probe_regex() {
    printf '%s\n' "$PROBES" |
        awk 'NF >= 2 { printf "%s%s", sep, $1; sep = "|" }'
}

# Replace handler=0x... with handler=SYMBOL+offset using the live kallsyms.
# kptr_restrict is 2 on this device, so root has to drop it to 0 for the
# duration of the read and put it back afterwards.
resolve_handlers() {
    trace=$1
    if ! grep -q 'handler=0x' "$trace"; then
        cat "$trace"
        return
    fi
    ks=$(mktemp)
    $ADB shell 'su -c "sh -s"' >"$ks" <<'EOF'
orig=$(cat /proc/sys/kernel/kptr_restrict)
echo 0 > /proc/sys/kernel/kptr_restrict 2>/dev/null || true
grep '\[pvrsrvkm\]' /proc/kallsyms
echo "$orig" > /proc/sys/kernel/kptr_restrict 2>/dev/null || true
EOF
    python3 - "$ks" "$trace" <<'PY'
import bisect, re, sys
ks, tr = sys.argv[1], sys.argv[2]
syms = []
for line in open(ks):
    p = line.split()
    if len(p) >= 3:
        try:
            syms.append((int(p[0], 16), p[2]))
        except ValueError:
            pass
syms.sort()
addrs = [a for a, _ in syms]

def resolve(a):
    i = bisect.bisect_right(addrs, a) - 1
    return "?" if i < 0 else "%s+0x%x" % (syms[i][1], a - syms[i][0])

pat = re.compile(r'handler=(0x[0-9a-f]+)')
for line in open(tr):
    sys.stdout.write(pat.sub(lambda m: 'handler=' + resolve(int(m.group(1), 16)), line))
PY
    rm -f "$ks"
}

# Emit the registration lines. $1 = list (report to stdout) or run (stderr).
emit_probes() {
    printf '%s\n' "$PROBES" |
    while read -r name sym args; do
        [ -n "${name:-}" ] || continue
        if [ "$1" = list ]; then
            inner="if echo 'p:$name $sym $args' >> \$T/kprobe_events 2>/dev/null; then echo 'OK   $name -> $sym $args'; else echo 'FAIL $name -> $sym $args'; fi"
            skipped="echo 'SKIP $name (running module build id is not $PINNED_BUILD_ID)'"
        else
            inner="echo 'p:$name $sym $args' >> \$T/kprobe_events 2>/dev/null || echo '(probe $name unavailable)' >&2"
            skipped="echo '(probe $name skipped: running module build id is not $PINNED_BUILD_ID)' >&2"
        fi
        if [ "$name" = pvrhandler ]; then
            printf '%s\n' "if [ \"\$BID_OK\" = 1 ]; then"
            printf '%s\n' "    $inner"
            printf '%s\n' "else"
            printf '%s\n' "    $skipped"
            printf '%s\n' "fi"
        else
            printf '%s\n' "$inner"
        fi
    done
}

remote_header() {
    cat <<EOF
#!/system/bin/sh
T=$T
BID=\$(od -An -tx1 /sys/module/pvrsrvkm/notes/.note.gnu.build-id 2>/dev/null | tr -d ' \\n' | tail -c 16)
if [ "\$BID" = "$PINNED_BUILD_ID" ]; then BID_OK=1; else BID_OK=0; fi
cleanup() {
    echo 0 > \$T/events/enable 2>/dev/null
    echo > \$T/kprobe_events 2>/dev/null
}
trap cleanup EXIT
echo 0 > \$T/tracing_on
echo 0 > \$T/events/enable
echo 16384 > \$T/buffer_size_kb 2>/dev/null || true
echo > \$T/trace
echo > \$T/kprobe_events 2>/dev/null || true
EOF
}

cmd=${1:-}
[ -n "$cmd" ] || usage

case "$cmd" in

list)
    {
        remote_header
        emit_probes list
    } | $ADB shell 'su -c "sh -s"'
    ;;

run)
    workload=${2:-gles}
    secs=${3:-3}

    case "$workload" in
    gles)
        wl="chroot $CH /usr/bin/env -i HOME=/root PATH=/usr/bin:/bin DISPLAY=:1 \
            /opt/pvr-bridge/opengl/bin/run-x11-gles \
            /opt/pvr-bridge/opengl/bin/egl-gles2-smoke"
        ;;
    vulkan)
        wl="chroot $CH /usr/bin/env -i HOME=/root PATH=/usr/bin:/bin DISPLAY=:1 \
            /bin/sh -c '. /opt/pvr-bridge/bin/pvr-env && exec /usr/bin/vulkaninfo --summary'"
        ;;
    vaapi)
        wl="chroot $CH /usr/bin/env -i HOME=/root PATH=/usr/bin:/bin DISPLAY=:1 \
            /opt/pvr-bridge/video/bin/va-pvr-env \
            ffmpeg -nostdin -hide_banner -v error -vaapi_device :1 -hwaccel vaapi \
            -hwaccel_output_format vaapi -i /tmp/hv480b2.h265 -f null -"
        ;;
    idle)
        wl="sleep $secs"
        ;;
    *)
        echo "unknown workload: $workload" >&2
        usage
        ;;
    esac

    out=$(mktemp)
    {
        remote_header
        emit_probes run
        cat <<EOF
if ! echo 1 > \$T/events/kprobes/enable 2>/dev/null; then
    echo 'no kprobe events registered' >&2
    exit 1
fi
echo 1 > \$T/tracing_on
timeout $((secs + 30)) sh -c "$wl" >/dev/null 2>&1 || true
sleep 1
echo 0 > \$T/tracing_on
grep -E ': ($(probe_regex)):' \$T/trace || true
EOF
    } | $ADB shell 'su -c "sh -s"' >"$out"

    resolve_handlers "$out"
    rm -f "$out"
    ;;

*)
    usage
    ;;
esac
