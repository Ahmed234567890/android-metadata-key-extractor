#!/bin/sh
# Verify the archived artifacts against their recorded hashes.
#
#   ./scripts/verify.sh            # repository files only
#   ./scripts/verify.sh --release  # also check downloaded release assets
set -eu

HERE=$(cd "$(dirname "$0")/.." && pwd)
cd "$HERE"

status=0

echo "== repository files"
if sha256sum -c MANIFEST.sha256; then
    echo "OK: repository files match"
else
    status=1
fi

if [ "${1:-}" = "--release" ]; then
    echo "== release assets"
    if [ -f RELEASE.sha256 ]; then
        if sha256sum -c RELEASE.sha256; then
            echo "OK: release assets match"
        else
            status=1
        fi
    else
        echo "RELEASE.sha256 missing"
        status=1
    fi
fi

echo "== running module vs archived module"
if command -v adb >/dev/null 2>&1; then
    SERIAL=${SERIAL:-}
    ADB="adb ${SERIAL:+-s $SERIAL}"
    live=$($ADB shell 'su -c "od -An -tx1 /sys/module/pvrsrvkm/notes/.note.gnu.build-id"' 2>/dev/null | tr -d ' \r\n' | tail -c 16 || true)
    if [ -n "$live" ]; then
        echo "build id on device: $live"
        echo "build id in file:   $(readelf -n modules/pvrsrvkm.ko 2>/dev/null | awk '/Build ID/{print $3}')"
    else
        echo "(device not reachable, skipped)"
    fi
fi

exit $status
