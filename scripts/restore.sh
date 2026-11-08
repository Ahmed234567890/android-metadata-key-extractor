#!/bin/sh
# Put the stock artifacts back.
#
#   ./scripts/restore.sh module   # restore pvrsrvkm.ko on /mnt/vendor/socko
#   ./scripts/restore.sh boot     # restore boot.img to mmcblk0p40
#
# Both paths write to the device and reboot it. Read the output before
# confirming; there is no undo other than the archive itself.
set -eu

SERIAL=${SERIAL:-}
ADB="adb ${SERIAL:+-s $SERIAL}"
HERE=$(cd "$(dirname "$0")/.." && pwd)

case "${1:-}" in

module)
    echo "This will overwrite /mnt/vendor/socko/pvrsrvkm.ko on the device"
    echo "with the archived copy, remount it read-only and reboot."
    printf 'Continue? [y/N] '
    read -r ans
    [ "$ans" = "y" ] || exit 1

    $ADB push "$HERE/modules/pvrsrvkm.ko" /data/local/tmp/pvrsrvkm.stock.ko
    $ADB shell 'su -c "
        set -e
        mount -o remount,rw /mnt/vendor/socko
        cp /data/local/tmp/pvrsrvkm.stock.ko /mnt/vendor/socko/pvrsrvkm.ko
        sync
        mount -o remount,ro /mnt/vendor/socko
        sha256sum /mnt/vendor/socko/pvrsrvkm.ko
    "'
    echo "expected: 6843bf0ee967ba623dc5038e1967f0769c083f18b6a0c5b91f4ddfdf19486d2c"
    echo "rebooting"
    $ADB reboot
    ;;

boot)
    echo "This will write boot.img over mmcblk0p40 (64 MiB)."
    printf 'Continue? [y/N] '
    read -r ans
    [ "$ans" = "y" ] || exit 1

    if [ ! -f "$HERE/raw/release/boot.img.zst" ]; then
        echo "missing raw/release/boot.img.zst"
        echo "download it: gh release download stock-2026-11-01 --repo Ahmed234567890/proprietary-stuff"
        exit 1
    fi

    zstd -d -f "$HERE/raw/release/boot.img.zst" -o /tmp/boot.restore.img
    echo "restoring; do not interrupt"
    $ADB push /tmp/boot.restore.img /data/local/tmp/boot.restore.img
    $ADB shell 'su -c "
        set -e
        dd if=/data/local/tmp/boot.restore.img of=/dev/block/by-name/boot bs=1M
        sync
    "'
    echo "rebooting"
    $ADB reboot
    ;;

*)
    echo "usage: $0 {module|boot}"
    exit 2
    ;;
esac
