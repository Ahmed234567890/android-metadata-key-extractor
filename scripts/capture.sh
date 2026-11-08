#!/bin/sh
# Capture the stock boot image and vendor kernel modules from the device.
#
#   SERIAL=192.168.1.16:42503 ./scripts/capture.sh
#
# Everything is staged under /data/local/tmp/cap on the device as root and then
# pulled into raw/cap. The device is not modified beyond that staging directory,
# which is left behind so a failed run can be inspected.
set -eu

SERIAL=${SERIAL:-}
ADB="adb ${SERIAL:+-s $SERIAL}"
HERE=$(cd "$(dirname "$0")/.." && pwd)
OUT="$HERE/raw/cap"

echo "== staging on the device"
$ADB shell 'su -c "sh -s"' <<'SCRIPT'
set -e
rm -rf /data/local/tmp/cap
mkdir -p /data/local/tmp/cap/socko /data/local/tmp/cap/vendor-modules /data/local/tmp/cap/facts

cp /mnt/vendor/socko/*.ko        /data/local/tmp/cap/socko/
cp /vendor/lib/modules/*.ko      /data/local/tmp/cap/vendor-modules/ 2>/dev/null || true
cp /proc/config.gz               /data/local/tmp/cap/facts/kernel-config.gz

# Block devices cannot be pulled directly.
dd if=/dev/block/by-name/boot of=/data/local/tmp/cap/boot.img bs=1M 2>/dev/null

{
    uname -a
    getprop ro.build.fingerprint
    getprop ro.product.device
    getprop ro.boot.veritymode
} > /data/local/tmp/cap/facts/uname.txt

cat /proc/modules            > /data/local/tmp/cap/facts/proc-modules.txt
lsmod                        > /data/local/tmp/cap/facts/lsmod.txt
ls -la /mnt/vendor/socko     > /data/local/tmp/cap/facts/socko-listing.txt
ls -la /vendor/lib/modules   > /data/local/tmp/cap/facts/vendor-modules-listing.txt
mount                        > /data/local/tmp/cap/facts/mounts.txt
cat /proc/sys/kernel/tainted > /data/local/tmp/cap/facts/taint.txt
cat /sys/module/pvrsrvkm/taint >> /data/local/tmp/cap/facts/taint.txt
cat /proc/cmdline            > /data/local/tmp/cap/facts/cmdline.txt

for p in /sys/module/pvrsrvkm/parameters/*; do
    echo "$(basename "$p")=$(cat "$p" 2>/dev/null)"
done > /data/local/tmp/cap/facts/module-params.txt

find /sys/class/drm -maxdepth 1 \( -name 'card*' -o -name 'renderD*' \) \
    > /data/local/tmp/cap/facts/drm-nodes.txt

chmod -R 644 /data/local/tmp/cap/facts/* /data/local/tmp/cap/socko/* \
              /data/local/tmp/cap/vendor-modules/* /data/local/tmp/cap/boot.img
chmod 755 /data/local/tmp/cap /data/local/tmp/cap/socko \
          /data/local/tmp/cap/vendor-modules /data/local/tmp/cap/facts
SCRIPT

echo "== pulling into $OUT"
rm -rf "$OUT"
mkdir -p "$HERE/raw"
$ADB pull /data/local/tmp/cap "$OUT"

echo "== sanity"
size=$(stat -c %s "$OUT/boot.img")
echo "boot.img: $size bytes"
[ "$size" = "67108864" ] || echo "WARNING: expected 67108864 bytes for mmcblk0p40"

echo "== done; run scripts/verify.sh next"
