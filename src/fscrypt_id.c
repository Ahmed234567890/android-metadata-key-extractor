/* Static ARM32 tool: install a raw fscrypt v2 key into a mounted ext4/f2fs
 * filesystem keyring (in-memory only) and print the kernel-computed key
 * identifier.  Used to verify the HKDF identifier of a recovered key.
 *
 * Build:
 *   clang --target=armv7a-linux-gnueabi -nostdlib -static -O2 -ffreestanding \
 *     -fno-builtin -fno-stack-protector -fuse-ld=lld -o fscrypt_id fscrypt_id.c
 */
typedef unsigned char u8;
typedef unsigned int u32;

static long sys6(long n, long a, long b, long c, long d, long e, long f) {
    register long r7 __asm__("r7") = n;
    register long r0 __asm__("r0") = a;
    register long r1 __asm__("r1") = b;
    register long r2 __asm__("r2") = c;
    register long r3 __asm__("r3") = d;
    register long r4 __asm__("r4") = e;
    register long r5 __asm__("r5") = f;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r7), "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5) : "memory");
    return r0;
}
#define SYS_exit 1
#define SYS_read 3
#define SYS_write 4
#define SYS_open 5
#define SYS_close 6
#define SYS_ioctl 54

#define FS_IOC_ADD_ENCRYPTION_KEY 0xC0506617UL

static unsigned slen(const char *s) { unsigned n = 0; while (s[n]) n++; return n; }
static void puts_(const char *s) { sys6(SYS_write, 1, (long)s, slen(s), 0, 0, 0); }
static void putd(long v) {
    char b[24]; int i = 23; b[i] = '\n'; int neg = v < 0; unsigned long u = neg ? -v : v;
    if (!u) b[--i] = '0';
    while (u) { b[--i] = '0' + (u % 10); u /= 10; }
    if (neg) b[--i] = '-';
    sys6(SYS_write, 1, (long)(b + i), 24 - i, 0, 0, 0);
}
static void *memcpy_(void *d, const void *s, unsigned n) {
    u8 *dd = (u8 *)d; const u8 *ss = (const u8 *)s; while (n--) *dd++ = *ss++;
    return d;
}
static void *memset_(void *d, int c, unsigned n) {
    u8 *dd = (u8 *)d; while (n--) *dd++ = (u8)c; return d;
}
static long read_file(const char *path, u8 *buf, long cap) {
    long fd = sys6(SYS_open, (long)path, 0, 0, 0, 0, 0);
    if (fd < 0) return fd;
    long total = 0;
    while (total < cap) {
        long r = sys6(SYS_read, fd, (long)(buf + total), cap - total, 0, 0, 0);
        if (r <= 0) break;
        total += r;
    }
    sys6(SYS_close, fd, 0, 0, 0, 0, 0);
    return total;
}

static const char *DIR = "/mnt/f2test";
static const char *KEYPATH = "/tmp/dekey/system_de_key.bin";

void _start(void) {
    u8 key[64];
    long klen = read_file(KEYPATH, key, sizeof(key));
    puts_("key file "); puts_(KEYPATH); puts_(" len="); putd(klen);
    if (klen != 64) { puts_("need 64-byte key\n"); sys6(SYS_exit, 2, 0, 0, 0, 0, 0); }

    u8 arg[144];
    memset_(arg, 0, sizeof(arg));
    *(u32 *)(arg + 0) = 2;      /* FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER */
    *(u32 *)(arg + 40) = 64;    /* raw_size */
    memcpy_(arg + 80, key, 64);

    long fd = sys6(SYS_open, (long)DIR, 0x4000 /*O_DIRECTORY*/, 0, 0, 0, 0);
    if (fd < 0) { puts_("open dir failed "); puts_(DIR); puts_(" -> "); putd(fd); sys6(SYS_exit, 3, 0, 0, 0, 0, 0); }
    long rc = sys6(SYS_ioctl, fd, (long)FS_IOC_ADD_ENCRYPTION_KEY, (long)arg, 0, 0, 0);
    puts_("FS_IOC_ADD_ENCRYPTION_KEY rc="); putd(rc);
    puts_("identifier: ");
    for (int i = 0; i < 16; i++) {
        u32 b = arg[8 + i];
        char h[3]; h[0] = "0123456789abcdef"[(b >> 4) & 0xf]; h[1] = "0123456789abcdef"[b & 0xf]; h[2] = 0;
        sys6(SYS_write, 1, (long)h, 2, 0, 0, 0);
    }
    puts_("\n");
    sys6(SYS_close, fd, 0, 0, 0, 0, 0);
    sys6(SYS_exit, rc == 0 ? 0 : 4, 0, 0, 0, 0, 0);
}
