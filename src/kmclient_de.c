/* Static ARM32 TIPC client for the Trusty keymaster TA.
 * Replicates vold's system DE-key decrypt path:
 *   Configure -> BeginOperation(DECRYPT) -> UpdateOperation(body+tag) -> FinishOperation
 *
 * Build:
 *   PATH=/usr/lib/llvm22/bin:$PATH clang --target=armv7a-linux-gnueabi \
 *     -nostdlib -static -O2 -ffreestanding -fno-builtin -fno-stack-protector \
 *     -fuse-ld=lld -o kmclient kmclient.c
 */
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

static long sys6(long n, long a, long b, long c, long d, long e, long f) {
    register long r7 __asm__("r7") = n;
    register long r0 __asm__("r0") = a;
    register long r1 __asm__("r1") = b;
    register long r2 __asm__("r2") = c;
    register long r3 __asm__("r3") = d;
    register long r4 __asm__("r4") = e;
    register long r5 __asm__("r5") = f;
    __asm__ volatile("svc #0"
                     : "+r"(r0)
                     : "r"(r7), "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5)
                     : "memory");
    return r0;
}
#define SYS_exit 1
#define SYS_read 3
#define SYS_write 4
#define SYS_open 5
#define SYS_close 6
#define SYS_ioctl 54

#define TIPC_IOC_CONNECT 0x40047280UL

static unsigned slen(const char *s) { unsigned n = 0; while (s[n]) n++; return n; }
static void puts_(const char *s) { sys6(SYS_write, 1, (long)s, slen(s), 0, 0, 0); }
static void putc_(char c) { sys6(SYS_write, 1, (long)&c, 1, 0, 0, 0); }
static void putx(u32 v) {
    char b[11]; b[0] = '0'; b[1] = 'x';
    for (int i = 0; i < 8; i++) {
        u32 d = (v >> (28 - 4 * i)) & 0xf;
        b[2 + i] = d < 10 ? '0' + d : 'a' + d - 10;
    }
    b[10] = ' ';
    sys6(SYS_write, 1, (long)b, 11, 0, 0, 0);
}
static void putd(long v) {
    char b[24]; int i = 23; b[i] = '\n'; int neg = v < 0; unsigned long u = neg ? -v : v;
    if (!u) b[--i] = '0';
    while (u) { b[--i] = '0' + (u % 10); u /= 10; }
    if (neg) b[--i] = '-';
    sys6(SYS_write, 1, (long)(b + i), 24 - i, 0, 0, 0);
}
static void hexdump(const u8 *p, int n) {
    for (int i = 0; i < n; i++) {
        if (i % 16 == 0) { puts_("\n  "); }
        putx(p[i]);
    }
    puts_("\n");
}
static void *memcpy_(void *d, const void *s, unsigned n) {
    u8 *dd = (u8 *)d; const u8 *ss = (const u8 *)s;
    while (n--) *dd++ = *ss++;
    return d;
}
static void *memset_(void *d, int c, unsigned n) {
    u8 *dd = (u8 *)d; while (n--) *dd++ = (u8)c; return d;
}
static u32 get_u32(const u8 *p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}
static u64 get_u64(const u8 *p) {
    return (u64)get_u32(p) | ((u64)get_u32(p + 4) << 32);
}
static void put_u32(u8 *p, u32 v) {
    p[0] = v & 0xff; p[1] = (v >> 8) & 0xff; p[2] = (v >> 16) & 0xff; p[3] = (v >> 24) & 0xff;
}
static void put_u64(u8 *p, u64 v) {
    put_u32(p, (u32)v); put_u32(p + 4, (u32)(v >> 32));
}

static long read_file(const char *path, u8 *buf, long cap) {
    long fd = sys6(SYS_open, (long)path, 0, 0, 0, 0, 0);
    if (fd < 0) { puts_("open failed "); puts_(path); puts_(" -> "); putd(fd); return fd; }
    long total = 0;
    while (total < cap) {
        long r = sys6(SYS_read, fd, (long)(buf + total), cap - total, 0, 0, 0);
        if (r <= 0) break;
        total += r;
    }
    sys6(SYS_close, fd, 0, 0, 0, 0, 0);
    return total;
}
static long write_file(const char *path, const u8 *buf, long n) {
    long fd = sys6(SYS_open, (long)path, 0x241 /*O_WRONLY|O_CREAT|O_TRUNC*/, 0600, 0, 0, 0);
    if (fd < 0) { puts_("create failed "); puts_(path); puts_(" -> "); putd(fd); return fd; }
    long w = sys6(SYS_write, fd, (long)buf, n, 0, 0, 0);
    sys6(SYS_close, fd, 0, 0, 0, 0, 0);
    return w;
}

/* ---- AuthorizationSet builder ---- */
typedef struct {
    u8 indirect[512]; u32 indirect_len;
    u8 elems[512]; u32 elems_len; u32 count;
} AuthSet;
static void as_init(AuthSet *a) { memset_(a, 0, sizeof(*a)); }
static void as_u32(AuthSet *a, u32 tag, u32 val) {
    put_u32(a->elems + a->elems_len, tag); a->elems_len += 4;
    put_u32(a->elems + a->elems_len, val); a->elems_len += 4;
    a->count++;
}
static void as_bytes(AuthSet *a, u32 tag, const u8 *data, u32 len) {
    u32 off = a->indirect_len;
    memcpy_(a->indirect + a->indirect_len, data, len); a->indirect_len += len;
    put_u32(a->elems + a->elems_len, tag); a->elems_len += 4;
    put_u32(a->elems + a->elems_len, len); a->elems_len += 4;
    put_u32(a->elems + a->elems_len, off); a->elems_len += 4;
    a->count++;
}
static u32 as_serialize(AuthSet *a, u8 *out, u32 off) {
    put_u32(out + off, a->indirect_len); off += 4;
    memcpy_(out + off, a->indirect, a->indirect_len); off += a->indirect_len;
    put_u32(out + off, a->count); off += 4;
    put_u32(out + off, a->elems_len); off += 4;
    memcpy_(out + off, a->elems, a->elems_len); off += a->elems_len;
    return off;
}

static long fd = -1;

static long send_recv(const u8 *req, long reqlen, u8 *rsp, long rspcap) {
    long w = 0;
    while (w < reqlen) {
        long r = sys6(SYS_write, fd, (long)(req + w), reqlen - w, 0, 0, 0);
        if (r <= 0) { puts_("write failed "); putd(r); return r; }
        w += r;
    }
    long r = sys6(SYS_read, fd, (long)rsp, rspcap, 0, 0, 0);
    return r;
}

static void show_rsp(const char *label, const u8 *rsp, long n) {
    puts_(label); puts_(": len="); putd(n);
    if (n > 0) {
        puts_("  cmd="); putx(get_u32(rsp));
        if (n >= 8) { puts_(" error="); putd((long)(int)get_u32(rsp + 4)); }
        hexdump(rsp, n > 64 ? 64 : (int)n);
    }
}

void _start(void) {
    puts_("=== kmclient ===\n");
    fd = sys6(SYS_open, (long)"/dev/trusty-ipc-dev0", 2, 0, 0, 0, 0);
    if (fd < 0) { puts_("open tipc failed "); putd(fd); sys6(SYS_exit, 1, 0, 0, 0, 0, 0); }
    long rc = sys6(SYS_ioctl, fd, (long)TIPC_IOC_CONNECT, (long)"com.android.trusty.keymaster", 0, 0, 0);
    puts_("connect -> "); putd(rc);
    if (rc != 0) { sys6(SYS_exit, 2, 0, 0, 0, 0, 0); }

    u8 keyblob[1024]; long kblen = read_file("/tmp/dekey/keymaster_key_blob", keyblob, sizeof(keyblob));
    u8 upblob[2048]; long uplen = 0;
    u8 appid[256];   long appidlen = read_file("/tmp/dekey/appid.bin", appid, sizeof(appid));
    u8 enc[256];     long enclen = read_file("/tmp/dekey/encrypted_key", enc, sizeof(enc));
    puts_("keyblob="); putd(kblen); puts_("appid="); putd(appidlen); puts_("enc="); putd(enclen);
    if (kblen <= 0 || appidlen <= 0 || enclen != 92) { puts_("bad inputs\n"); sys6(SYS_exit, 3, 0, 0, 0, 0, 0); }

    u8 req[4096]; u8 rsp[8192]; long n; u32 off;

    /* --- GET_VERSION (KM_GET_VERSION = 7<<2 = 0x1c) --- */
    put_u32(req, 0x1c);
    n = send_recv(req, 4, rsp, sizeof(rsp));
    show_rsp("GET_VERSION", rsp, n);

    /* --- CONFIGURE (cmd 0x48) --- */
    off = 0;
    put_u32(req + off, 0x48); off += 4;
    put_u32(req + off, 999999); off += 4;      /* os_version: high enough */
    put_u32(req + off, 209912); off += 4;      /* os_patchlevel: YYYYMM */
    n = send_recv(req, off, rsp, sizeof(rsp));
    show_rsp("CONFIGURE", rsp, n);
    if (n >= 8 && get_u32(rsp + 4) != 0) {
        puts_("configure failed; trying 0,0\n");
        off = 0;
        put_u32(req + off, 0x48); off += 4;
        put_u32(req + off, 0); off += 4;
        put_u32(req + off, 0); off += 4;
        n = send_recv(req, off, rsp, sizeof(rsp));
        show_rsp("CONFIGURE(0,0)", rsp, n);
    }

    /* --- UPGRADE_KEY (cmd 0x44): raise key's OS patchlevel to the latched 202601 --- */
    off = 0;
    put_u32(req + off, 0x44); off += 4;
    put_u32(req + off, (u32)kblen); off += 4;
    memcpy_(req + off, keyblob, kblen); off += kblen;
    AuthSet uas; as_init(&uas);
    as_bytes(&uas, 0x90000259, appid, (u32)appidlen); /* TAG_APPLICATION_ID (needed to derive KEK) */
    off = as_serialize(&uas, req, off);
    puts_("UPGRADE req len="); putd((long)off);
    n = send_recv(req, off, rsp, sizeof(rsp));
    show_rsp("UPGRADE", rsp, n);
    if (n >= 8 && get_u32(rsp + 4) == 0 && n >= 12) {
        u32 ulen = get_u32(rsp + 8);
        if (ulen <= sizeof(upblob) && n >= 12 + (long)ulen) {
            memcpy_(upblob, rsp + 12, ulen);
            uplen = ulen;
            puts_("upgraded blob len="); putd(uplen);
            puts_("upgraded blob head:"); hexdump(upblob, ulen > 48 ? 48 : (int)ulen);
        }
    } else {
        puts_("upgrade failed; using original blob\n");
    }

    /* --- BEGIN_OPERATION (cmd 4) --- */
    const u8 *useblob = uplen > 0 ? upblob : keyblob;
    long uselen = uplen > 0 ? uplen : kblen;
    off = 0;
    put_u32(req + off, 4); off += 4;                 /* cmd */
    put_u32(req + off, 1); off += 4;                 /* purpose = DECRYPT */
    put_u32(req + off, (u32)uselen); off += 4;       /* key blob length */
    memcpy_(req + off, useblob, uselen); off += uselen;
    AuthSet as; as_init(&as);
    as_u32(&as, 0x300003EB, 128);                    /* TAG_MAC_LENGTH = 128 bits */
    as_u32(&as, 0x20000004, 32);                     /* TAG_BLOCK_MODE = GCM */
    as_u32(&as, 0x20000006, 1);                      /* TAG_PADDING = NONE */
    as_bytes(&as, 0x90000259, appid, (u32)appidlen); /* TAG_APPLICATION_ID */
    as_bytes(&as, 0x900003E9, enc, 12);              /* TAG_NONCE = IV */
    as_u32(&as, 0x20000001, 1);                      /* TAG_PURPOSE = DECRYPT */
    off = as_serialize(&as, req, off);
    puts_("BEGIN req len="); putd((long)off);
    n = send_recv(req, off, rsp, sizeof(rsp));
    show_rsp("BEGIN", rsp, n);
    if (n < 8) { sys6(SYS_exit, 4, 0, 0, 0, 0, 0); }
    u32 err = get_u32(rsp + 4);
    if (err != 0) { puts_("begin error\n"); sys6(SYS_exit, 5, 0, 0, 0, 0, 0); }
    if (n < 16) { puts_("begin short\n"); sys6(SYS_exit, 6, 0, 0, 0, 0, 0); }
    u64 op = get_u64(rsp + 8);
    puts_("op_handle="); putx((u32)op); putx((u32)(op >> 32));

    /* --- UPDATE_OPERATION (cmd 8) --- */
    off = 0;
    put_u32(req + off, 8); off += 4;
    put_u64(req + off, op); off += 8;
    put_u32(req + off, (u32)(enclen - 12)); off += 4; /* input = body+tag (80 B) */
    memcpy_(req + off, enc + 12, enclen - 12); off += (u32)(enclen - 12);
    put_u32(req + off, 0); off += 4;                  /* empty authset: indirect_size */
    put_u32(req + off, 0); off += 4;                  /* elems_count */
    put_u32(req + off, 0); off += 4;                  /* elems_bytes */
    puts_("UPDATE req len="); putd((long)off);
    n = send_recv(req, off, rsp, sizeof(rsp));
    show_rsp("UPDATE", rsp, n);
    if (n < 8) { sys6(SYS_exit, 7, 0, 0, 0, 0, 0); }
    err = get_u32(rsp + 4);
    if (err != 0) { puts_("update error\n"); sys6(SYS_exit, 8, 0, 0, 0, 0, 0); }

    u8 plain[512]; u32 plainlen = 0;
    if (n >= 12) {
        u32 olen = get_u32(rsp + 8);
        puts_("update output len="); putd(olen);
        if (olen <= sizeof(plain) && n >= 12 + (long)olen) {
            memcpy_(plain, rsp + 12, olen);
            plainlen = olen;
        }
        u32 consumed = get_u32(rsp + 12 + olen);
        puts_("input_consumed="); putd(consumed);
    }

    /* --- FINISH_OPERATION (cmd 0x0c) --- */
    off = 0;
    put_u32(req + off, 0x0c); off += 4;
    put_u64(req + off, op); off += 8;
    put_u32(req + off, 0); off += 4;   /* signature len */
    put_u32(req + off, 0); off += 4;   /* empty authset indirect */
    put_u32(req + off, 0); off += 4;   /* elems_count */
    put_u32(req + off, 0); off += 4;   /* elems_bytes */
    put_u32(req + off, 0); off += 4;   /* input len */
    puts_("FINISH req len="); putd((long)off);
    n = send_recv(req, off, rsp, sizeof(rsp));
    show_rsp("FINISH", rsp, n);
    if (n >= 8) {
        err = get_u32(rsp + 4);
        puts_("finish error="); putd((long)(int)err);
        if (err != 0) { puts_("tag verification failed\n"); }
    }

    if (plainlen > 0) {
        long w = write_file("/tmp/dekey/system_de_key.bin", plain, plainlen);
        puts_("wrote system_de_key.bin "); putd(w);
        puts_("plaintext:"); hexdump(plain, plainlen > 64 ? 64 : (int)plainlen);
    } else {
        puts_("no plaintext produced\n");
    }
    sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
