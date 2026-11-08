#!/bin/sh
# Measure pvrsrvkm behaviour over a fixed window.
#
#   ./scripts/stability.sh measure idle 10     # power cadence + bridge traffic
#   ./scripts/stability.sh measure gles 3
#   ./scripts/stability.sh stress gles 20      # repeat the smoke test 20 times
#   ./scripts/stability.sh sweep-debug-level   # PVRDebugLevel 7 / 1 / 0
#
# Output is one key=value line per metric followed by a short detail block, so
# two runs can be compared with diff.
#
# The device must be awake: with the screen off the compositor stops and the
# idle numbers collapse. The script does not change that state.
set -eu

SERIAL=${SERIAL:-}
ADB="adb ${SERIAL:+-s $SERIAL}"
CH=${CH:-/data/local/nhsystem/kali-armhf}
T=/sys/kernel/tracing
PINNED_BUILD_ID=ba3eed02545fe11c

usage() {
    sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
}

# Emit a remote script header: probe bookkeeping and a cleanup trap.
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
echo 'p:pwr_off RGXPrePowerState'  >> \$T/kprobe_events 2>/dev/null
echo 'p:pwr_on  RGXPostPowerState' >> \$T/kprobe_events 2>/dev/null
if [ "\$BID_OK" = 1 ]; then
    echo 'p:pvrcmd BridgedDispatchKM+0x470 cmd=+0(%x19):u32 fn=+4(%x19):u32' >> \$T/kprobe_events 2>/dev/null
fi
echo 1 > \$T/events/kprobes/enable 2>/dev/null || true
EOF
}

summary_awk() {
    cat <<'EOF'
    off=$(grep -c 'pwr_off:' "$T/trace" 2>/dev/null || true)
    on=$(grep -c 'pwr_on:' "$T/trace" 2>/dev/null || true)
    cmds=$(grep -c 'pvrcmd:' "$T/trace" 2>/dev/null || true)
    echo "power_off=${off:-0}"
    echo "power_on=${on:-0}"
    echo "bridge_calls=${cmds:-0}"
    echo "top_commands:"
    grep 'pvrcmd:' "$T/trace" 2>/dev/null | sed -n 's/.*cmd=\([0-9]*\) fn=\([0-9]*\).*/\1 \2/p' \
        | sort | uniq -c | sort -rn | head -6 | sed 's/^/  /'
EOF
}

fd_count() {
    $ADB shell 'su -c "ls -l /proc/*/fd/* 2>/dev/null | grep -c renderD128"' 2>/dev/null | tr -d '\r' || echo 0
}

dmesg_count() {
    $ADB shell 'su -c "dmesg | grep -icE \"pvrsrv|rogue|rgx\""' 2>/dev/null | tr -d '\r' || echo 0
}

cmd=${1:-}
[ -n "$cmd" ] || usage

case "$cmd" in

measure)
    workload=${2:-idle}
    secs=${3:-10}

    case "$workload" in
    idle) wl="sleep $secs" ;;
    gles) wl="chroot $CH /usr/bin/env -i HOME=/root PATH=/usr/bin:/bin DISPLAY=:1 \
              /opt/pvr-bridge/opengl/bin/run-x11-gles \
              /opt/pvr-bridge/opengl/bin/egl-gles2-smoke" ;;
    vulkan) wl="chroot $CH /usr/bin/env -i HOME=/root PATH=/usr/bin:/bin DISPLAY=:1 \
                /bin/sh -c '. /opt/pvr-bridge/bin/pvr-env && exec /usr/bin/vulkaninfo --summary'" ;;
    *) echo "unknown workload: $workload" >&2; usage ;;
    esac

    fds_before=$(fd_count)
    dmesg_before=$(dmesg_count)
    level=$($ADB shell 'su -c "cat /sys/module/pvrsrvkm/parameters/PVRDebugLevel"' 2>/dev/null | tr -d '\r')

    {
        remote_header
        cat <<EOF
echo 1 > \$T/tracing_on
timeout $((secs + 30)) sh -c "$wl" >/dev/null 2>&1 || true
sleep 1
echo 0 > \$T/tracing_on
$(summary_awk)
EOF
    } | $ADB shell 'su -c "sh -s"'

    fds_after=$(fd_count)
    dmesg_after=$(dmesg_count)

    echo "workload=$workload"
    echo "seconds=$secs"
    echo "pvrdebuglevel=${level:-?}"
    echo "render_fds_before=$fds_before"
    echo "render_fds_after=$fds_after"
    echo "dmesg_gpu_lines_before=$dmesg_before"
    echo "dmesg_gpu_lines_after=$dmesg_after"
    ;;

stress)
    workload=${2:-gles}
    runs=${3:-20}

    case "$workload" in
    gles) wl="chroot $CH /usr/bin/env -i HOME=/root PATH=/usr/bin:/bin DISPLAY=:1 \
              /opt/pvr-bridge/opengl/bin/run-x11-gles \
              /opt/pvr-bridge/opengl/bin/egl-gles2-smoke" ;;
    vulkan) wl="chroot $CH /usr/bin/env -i HOME=/root PATH=/usr/bin:/bin DISPLAY=:1 \
              /bin/sh -c '. /opt/pvr-bridge/bin/pvr-env && exec /usr/bin/vulkaninfo --summary'" ;;
    mixed) wl="" ;;
    *) echo "stress supports gles, vulkan and mixed" >&2; usage ;;
    esac

    fds_before=$(fd_count)
    dmesg_before=$(dmesg_count)
    mem_before=$($ADB shell 'su -c "grep MemAvailable /proc/meminfo"' 2>/dev/null | tr -dc '0-9')
    level=$($ADB shell 'su -c "cat /sys/module/pvrsrvkm/parameters/PVRDebugLevel"' 2>/dev/null | tr -d '\r')

    if [ "$workload" = mixed ]; then
        gl="chroot $CH /usr/bin/env -i HOME=/root PATH=/usr/bin:/bin DISPLAY=:1 /opt/pvr-bridge/opengl/bin/run-x11-gles /opt/pvr-bridge/opengl/bin/egl-gles2-smoke"
        vk="chroot $CH /usr/bin/env -i HOME=/root PATH=/usr/bin:/bin DISPLAY=:1 /bin/sh -c '. /opt/pvr-bridge/bin/pvr-env && exec /usr/bin/vulkaninfo --summary'"
        body='    if [ $((n % 3)) -eq 0 ]; then
        if timeout 60 sh -c "'"$vk"'" >/dev/null 2>&1; then pass=$((pass+1)); else fail=$((fail+1)); fi
    else
        if timeout 60 sh -c "'"$gl"'" >/dev/null 2>&1; then pass=$((pass+1)); else fail=$((fail+1)); fi
    fi'
    else
        body='    if timeout 60 sh -c "'"$wl"'" >/dev/null 2>&1; then pass=$((pass+1)); else fail=$((fail+1)); fi'
    fi

    {
        remote_header
        cat <<EOF
echo 1 > \$T/tracing_on
pass=0; fail=0; n=0
start=\$(date +%s)
while [ \$n -lt $runs ]; do
    n=\$((n + 1))
$body
done
end=\$(date +%s)
echo 0 > \$T/tracing_on
echo "runs=\$n"
echo "pass=\$pass"
echo "fail=\$fail"
echo "seconds=\$((end - start))"
echo "power_off=\$(grep -c 'pwr_off:' \$T/trace 2>/dev/null || true)"
echo "power_on=\$(grep -c 'pwr_on:' \$T/trace 2>/dev/null || true)"
echo "bridge_calls=\$(grep -c 'pvrcmd:' \$T/trace 2>/dev/null || true)"
EOF
    } | $ADB shell 'su -c "sh -s"'

    fds_after=$(fd_count)
    dmesg_after=$(dmesg_count)
    mem_after=$($ADB shell 'su -c "grep MemAvailable /proc/meminfo"' 2>/dev/null | tr -dc '0-9')

    echo "workload=$workload"
    echo "pvrdebuglevel=${level:-?}"
    echo "render_fds_before=$fds_before"
    echo "render_fds_after=$fds_after"
    echo "mem_available_kb_before=${mem_before:-?}"
    echo "mem_available_kb_after=${mem_after:-?}"
    echo "dmesg_gpu_lines_before=$dmesg_before"
    echo "dmesg_gpu_lines_after=$dmesg_after"
    ;;

sweep-debug-level)
    echo "== baseline (7)"
    SERIAL=$SERIAL "$0" measure idle 10
    for lvl in 1 0; do
        echo "== PVRDebugLevel=$lvl"
        $ADB shell "su -c 'echo $lvl > /sys/module/pvrsrvkm/parameters/PVRDebugLevel'"
        sleep 1
        SERIAL=$SERIAL "$0" measure idle 10
    done
    $ADB shell "su -c 'echo 7 > /sys/module/pvrsrvkm/parameters/PVRDebugLevel'"
    echo "restored PVRDebugLevel=7"
    ;;

*)
    usage
    ;;
esac
