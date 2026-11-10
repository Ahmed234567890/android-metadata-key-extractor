# Recovery source code

Static ARM32 (armv7a / armv8l, `-target=armv7a-linux-gnueabi`) freestanding userspace tools used
during the SM-A032F metadata-key recovery. Built with:

```sh
clang --target=armv7a-linux-gnueabi -nostdlib -static -O2 -ffreestanding \
  -fno-builtin -fno-stack-protector -fuse-ld=lld -o <out> <src>.c
```

| File | Purpose |
| --- | --- |
| [`dmkey.c`](dmkey.c) | Minimal device-mapper ioctl client; creates/removes/queries dm devices and loads `default-key` tables (used for the `dm-default-key` mapping of `/data`). |
| [`kmclient_de.c`](kmclient_de.c) | Static TIPC client for the Trusty keymaster TA (`com.android.trusty.keymaster`); replicates vold's system-DE-key decrypt sequence: `CONFIGURE` → `UPGRADE_KEY` → `BEGIN` → `UPDATE` → `FINISH`. |
| [`fscrypt_id.c`](fscrypt_id.c) | Installs a raw fscrypt v2 key into the kernel keyring and prints the kernel-computed key identifier. |
| [`fscrypt_ce.c`](fscrypt_ce.c) | Installs a recovered fscrypt key (CE class) and dumps the filesystem key policy xattr. |

See [`../docs/KEY_RECOVERY.md`](../docs/KEY_RECOVERY.md) for the procedure these tools support and
[`../docs/RECOVERY.md`](../docs/RECOVERY.md) for the full recovery context.
