#!/bin/sh
# Read-only re-check of the SM-A032F recovery images.
#
#   IMG_DIR=/home/ahmed ./recovery/verify.sh
#   IMG_DIR=/home/ahmed ./recovery/verify.sh --full   # also re-hash everything
#
# Never writes to the images. Exits non-zero if a required image is missing.
set -eu

IMG_DIR=${IMG_DIR:-/home/ahmed}
HERE=$(cd "$(dirname "$0")" && pwd)
FULL=0
[ "${1:-}" = "--full" ] && FULL=1

say() { printf '%s\n' "$*"; }

say "== images in $IMG_DIR"
missing=0
for f in userdata.img userdata_encrypted.img userdata.trim.img \
         metadata.img metadata.trim.img misc_p8_backup.img \
         boot_p40_backup.img bootchk/boot_unrooted.img; do
    p="$IMG_DIR/$f"
    if [ -f "$p" ]; then
        say "$(stat -c '%s' "$p")  $f"
    else
        say "MISSING  $f"
        missing=1
    fi
done

say "== sha256"
if [ "$FULL" = 1 ] && [ -f "$HERE/hashes.txt" ]; then
    ( cd "$IMG_DIR" && grep -v '^#' "$HERE/hashes.txt" | sha256sum -c - ) || true
else
    say "(skipped; pass --full to re-hash)"
fi

say "== userdata must be ciphertext (no fs magic)"
if [ -f "$IMG_DIR/userdata.img" ]; then
    f2fs=$(dd if="$IMG_DIR/userdata.img" bs=1 skip=$((0x400)) count=4 2>/dev/null | od -An -tx1 | tr -d ' \n')
    ext4=$(dd if="$IMG_DIR/userdata.img" bs=1 skip=$((0x438)) count=2 2>/dev/null | od -An -tx1 | tr -d ' \n')
    say "f2fs magic @0x400: $f2fs  (expect not 1020f5f2)"
    say "ext4 magic @0x438: $ext4  (expect not 53ef)"
fi

say "== metadata key files"
if [ -f "$IMG_DIR/metadata.img" ]; then
    debugfs -R 'ls -l /vold/metadata_encryption/key' "$IMG_DIR/metadata.img" 2>/dev/null
fi

say "== misc BCB"
if [ -f "$IMG_DIR/misc_p8_backup.img" ]; then
    strings -a "$IMG_DIR/misc_p8_backup.img" | head -5
fi

say "== boot images"
if [ -f "$IMG_DIR/boot_p40_backup.img" ] && [ -f "$IMG_DIR/bootchk/boot_unrooted.img" ]; then
    sha256sum "$IMG_DIR/boot_p40_backup.img" "$IMG_DIR/bootchk/boot_unrooted.img"
fi

exit "$missing"
