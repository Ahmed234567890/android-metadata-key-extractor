#!/usr/bin/env python3
"""Offline f2fs + fscrypt v2 extractor for SM-A032F userdata.

Metadata (NAT, inodes, dentries) is read from the dm-default-key decrypted
snapshot (userdata_dec.img).  Encrypted file contents are read from the raw
partition snapshot (userdata.img), where they are stored as true fscrypt
ciphertext.  Unencrypted file contents are read from the metadata snapshot.

Verified against known-good copies: photo ino 345689 and ELF ino 618437.
"""
import argparse
import hashlib
import hmac
import json
import os
import struct
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

META_IMG = '/home/ahmed/userdata_dec.img'
RAW_IMG = '/home/ahmed/userdata.img'
BS = 4096
BLOCK_COUNT = 6532087
MAIN_BLKADDR = 45056
NAT_BASE = 2560
NAT_PER = 455
BLKS_PER_SEG = 512
ADDRS_PER_INODE = 923
ADDRS_PER_NODE = 1018

CE_KEY_FILE = '/home/ahmed/sp/ce_key.bin'
DE_KEY_FILE = '/home/ahmed/dekey/system_de_key.bin'
FS_UUID = bytes.fromhex('d287e4877e6d49fb8a0b62acda88be54')

# The host snapshot predates mountfix.  The phone's patched NAT area holds the
# complete twin of every checkpoint-redirected NAT pair, so prefer it for NAT
# lookups.  Values not present in this overlay fall back to the host snapshot.
NAT_OVERRIDE_IMG = '/home/ahmed/userdata_nat_patched.img'
NAT_OVERRIDE_BASE = 2560
NAT_OVERRIDE_BLOCKS = 29696
CP2_PATCHED = '/home/ahmed/cp2_patched.bin'
NAT_JOURNAL_BLOCK = 1025
NAT_JOURNAL_OFF = 3584
NAT_JOURNAL_ENTRY = 13
NAT_JOURNAL_MAX = 38

FT_REG, FT_DIR, FT_CHR, FT_BLK, FT_FIFO, FT_SOCK, FT_SYMLINK = 1, 2, 3, 4, 5, 6, 7

u16 = lambda b, o: struct.unpack_from('<H', b, o)[0]
u32 = lambda b, o: struct.unpack_from('<I', b, o)[0]
u64 = lambda b, o: struct.unpack_from('<Q', b, o)[0]
le64 = lambda x: struct.pack('<Q', x)


def hkdf_expand(prk, context, info, outlen):
    okm = b''
    i = 1
    while len(okm) < outlen:
        okm += hmac.new(prk, b'fscrypt\x00' + bytes([context]) + info +
                        bytes([i]), hashlib.sha512).digest()
        i += 1
    return okm[:outlen]


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def cbc_decrypt(key, iv, data):
    c = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return c.update(data) + c.finalize()


def xts_decrypt(key, iv, data):
    c = Cipher(algorithms.AES(key), modes.XTS(iv)).decryptor()
    return c.update(data) + c.finalize()


class MasterKey:
    def __init__(self, raw):
        self.raw = raw
        prk = hmac.new(b'\x00' * 64, raw, hashlib.sha512).digest()
        self.ident = hkdf_expand(prk, 1, b'', 16)
        # IV_INO_LBLK_64 contents key, XTS mode number 1
        self.contents = hkdf_expand(prk, 4, bytes([1]) + FS_UUID, 64)
        # AES-256-CTS filenames key, mode number 4
        self.filenames = hkdf_expand(prk, 4, bytes([4]) + FS_UUID, 32)

    def matches(self, key_id):
        return hmac.compare_digest(self.ident, key_id)


class F2FS:
    def __init__(self, meta_path=META_IMG):
        self.meta = open(meta_path, 'rb')
        self.raw = open(RAW_IMG, 'rb')
        self.meta.seek(1024)
        sb = self.meta.read(3072)
        self.uuid = sb[108:124]
        self.root_ino = u32(sb, 96)
        self.nat_blkaddr = u32(sb, 84)
        self.main_blkaddr = u32(sb, 92)
        assert self.uuid == FS_UUID, (self.uuid.hex(), FS_UUID.hex())
        self.mkeys = []
        for path in (CE_KEY_FILE, DE_KEY_FILE):
            with open(path, 'rb') as f:
                self.mkeys.append(MasterKey(f.read()))
        self._inode_cache = {}
        self.nat = open(NAT_OVERRIDE_IMG, 'rb')
        cp2 = open(CP2_PATCHED, 'rb').read(BS)
        sitb = u32(cp2, 156)
        natb = u32(cp2, 160)
        self.nat_bitmap = cp2[192 + sitb:192 + sitb + natb]
        # Authoritative NAT journal from the selected checkpoint's hot-data
        # summary block (normal, non-compact layout for this checkpoint).
        self.journal = {}
        jb = self.mblk(NAT_JOURNAL_BLOCK)
        n = u16(jb, NAT_JOURNAL_OFF)
        if 0 < n <= NAT_JOURNAL_MAX:
            for i in range(n):
                o = NAT_JOURNAL_OFF + 2 + i * NAT_JOURNAL_ENTRY
                nid, ver, ino, blk = struct.unpack_from('<IBII', jb, o)
                self.journal[nid] = (ver, ino, blk)

    # ---------------- low level ----------------
    def mblk(self, blk):
        self.meta.seek(blk * BS)
        return self.meta.read(BS)

    def nat_block(self, blk):
        if NAT_OVERRIDE_BASE <= blk < NAT_OVERRIDE_BASE + NAT_OVERRIDE_BLOCKS:
            self.nat.seek((blk - NAT_OVERRIDE_BASE) * BS)
            return self.nat.read(BS)
        return self.mblk(blk)

    def nat_selected(self, block_off):
        return (self.nat_bitmap[block_off >> 3] >> (block_off & 7)) & 1

    def rblk(self, blk):
        self.raw.seek(blk * BS)
        return self.raw.read(BS)

    def nat_entry(self, nid):
        # A checkpoint NAT-journal entry always overrides the NAT block.  An
        # entry with block address 0 means the node was freed.
        if nid in self.journal:
            return self.journal[nid]
        bo = nid // NAT_PER
        base = NAT_BASE + (bo << 1) - (bo & (BLKS_PER_SEG - 1))
        sel = self.nat_selected(bo)
        copies = (base, base + BLKS_PER_SEG)
        best = None
        for which in (sel, 1 - sel):
            a = copies[which]
            if a + 1 >= BLOCK_COUNT:
                continue
            nat = self.nat_block(a)
            o = (nid - bo * NAT_PER) * 9
            ver, ino, blk = nat[o], u32(nat, o + 1), u32(nat, o + 5)
            if not blk or not (MAIN_BLKADDR <= blk < BLOCK_COUNT):
                continue
            node = self.mblk(blk)
            if u32(node, 4072) != nid:
                continue
            # Prefer the checkpoint-selected copy on a version tie.
            if best is None or ver > best[0] or (
                    ver == best[0] and which == sel):
                best = (ver, ino, blk)
        return best

    def inode(self, ino):
        if ino in self._inode_cache:
            return self._inode_cache[ino]
        ne = self.nat_entry(ino)
        if ne is None or ne[2] == 0:
            return None
        ver, nino, blk = ne
        n = self.mblk(blk)
        if u32(n, 4076) != ino:
            return None
        inline = n[3]
        extra = u16(n, 360) if inline & 0x20 else 0
        extra_units = extra // 4
        ix_units = u16(n, 362) if inline & 0x20 else 0
        if (inline & 0x01 or inline & 0x04) and ix_units == 0:
            ix_units = 50
        inode = dict(
            ino=ino, iblk=blk, raw=n, mode=u16(n, 0), inline=inline,
            size=u64(n, 16), flags=u32(n, 80), pino=u32(n, 84),
            extra=extra, extra_units=extra_units, ix_units=ix_units,
            direct_start=extra_units, direct_end=ADDRS_PER_INODE - ix_units,
            nids=[u32(n, 4052 + 4 * i) for i in range(5)],
        )
        self._inode_cache[ino] = inode
        return inode

    def direct_addrs(self, inode):
        n = inode['raw']
        return [u32(n, 360 + 4 * i)
                for i in range(inode['direct_start'], inode['direct_end'])]

    def node_addrs(self, nid, owner_ino, indirect=False):
        ne = self.nat_entry(nid)
        if ne is None or ne[2] == 0:
            return []
        ver, nino, blk = ne
        n = self.mblk(blk)
        if u32(n, 4072) != nid:
            return []
        if indirect:
            out = []
            for i in range(ADDRS_PER_NODE):
                child = u32(n, 4 * i)
                if child:
                    out.extend(self.node_addrs(child, owner_ino, False))
            return out
        return [u32(n, 4 * i) for i in range(ADDRS_PER_NODE)]

    def block_map(self, inode, nblocks):
        """Logical block map, including zero entries for holes."""
        addrs = self.direct_addrs(inode)
        for k in (0, 1):
            nid = inode['nids'][k]
            if nid:
                addrs += self.node_addrs(nid, inode['ino'], False)
        for k, kind in ((2, 'IND1'), (3, 'IND2'), (4, 'DIND')):
            nid = inode['nids'][k]
            if not nid:
                continue
            ne = self.nat_entry(nid)
            if not ne or not ne[2]:
                continue
            n = self.mblk(ne[2])
            children = []
            for i in range(ADDRS_PER_NODE):
                v = u32(n, 4 * i)
                if v and (MAIN_BLKADDR <= v < BLOCK_COUNT):
                    children.append(v)
            if kind == 'IND1':
                addrs += children
            elif kind == 'IND2':
                # children of an IND2 node are IND1 node nids
                for ch in children:
                    ne2 = self.nat_entry(ch)
                    if not ne2 or not ne2[2]:
                        continue
                    n2 = self.mblk(ne2[2])
                    for i in range(ADDRS_PER_NODE):
                        v = u32(n2, 4 * i)
                        if v and (MAIN_BLKADDR <= v < BLOCK_COUNT):
                            addrs.append(v)
            else:
                # children of a DIND node are IND2 node nids
                for ch in children:
                    ne2 = self.nat_entry(ch)
                    if not ne2 or not ne2[2]:
                        continue
                    n2 = self.mblk(ne2[2])
                    for i in range(ADDRS_PER_NODE):
                        v = u32(n2, 4 * i)
                        if not v:
                            continue
                        ne3 = self.nat_entry(v)
                        n3 = self.mblk(ne3[2])
                        for j in range(ADDRS_PER_NODE):
                            w = u32(n3, 4 * j)
                            if w and (MAIN_BLKADDR <= w < BLOCK_COUNT):
                                addrs.append(w)
        return addrs[:nblocks]

    # ---------------- fscrypt ----------------
    def context(self, inode):
        """Return (key_id, contents_mode, filenames_mode, flags, nonce)."""
        n = inode['raw']
        ix_units = inode['ix_units']
        candidates = []
        if ix_units:
            start = 4052 - ix_units * 4
            candidates.append(n[start:4052])
        xnid = u32(n, 76)
        if xnid:
            ne = self.nat_entry(xnid)
            if ne:
                candidates.append(self.mblk(ne[2])[:4072])
        for area in candidates:
            pos = area.find(b'\x09\x01\x28\x00c')
            if pos < 0:
                # Flexible xattr header layouts: scan for index 9, name 'c'
                for p in range(0, max(0, len(area) - 45)):
                    if area[p] == 9 and area[p + 1] == 1 and area[p + 4] == 0x63:
                        vs = u16(area, p + 2)
                        if vs >= 40:
                            pos = p
                            break
            if pos < 0 or pos + 5 + 40 > len(area):
                continue
            val = area[pos + 5:pos + 45]
            if val[0] not in (1, 2):
                continue
            if val[0] == 1:
                key_id = val[4:12] + b'\x00' * 8
                nonce = val[12:28]
            else:
                key_id, nonce = val[8:24], val[24:40]
            return key_id, val[1], val[2], val[3], nonce
        return None

    def key_for(self, inode):
        ctx = self.context(inode)
        if ctx is None:
            return None, None
        key_id = ctx[0]
        for mk in self.mkeys:
            if mk.matches(key_id):
                return mk, ctx
        return None, ctx

    def decrypt_name(self, dir_inode, raw_name, mk):
        if raw_name in (b'.', b'..'):
            return raw_name
        if len(raw_name) < 16 or len(raw_name) % 16:
            return None
        iv = le64(dir_inode['ino'] << 32) + b'\x00' * 8
        if len(raw_name) == 16:
            pt = cbc_decrypt(mk.filenames, iv, raw_name)
        else:
            blocks = [raw_name[i:i + 16] for i in range(0, len(raw_name), 16)]
            blocks[-1], blocks[-2] = blocks[-2], blocks[-1]
            pt = cbc_decrypt(mk.filenames, iv, b''.join(blocks))
        return pt.split(b'\x00', 1)[0]

    def decrypt_content(self, inode, key):
        size = inode['size']
        nblocks = (size + BS - 1) // BS
        if inode['inline'] & 0x02:
            start = 360 + 4 * (inode['extra_units'] + 1)
            return inode['raw'][start:start + size]
        addrs = self.block_map(inode, nblocks)
        out = bytearray()
        for lblk, blk in enumerate(addrs):
            if len(out) >= size:
                break
            if blk == 0:
                out += b'\x00' * BS
                continue
            ct = self.rblk(blk)
            if key is None:
                pt = self.mblk(blk)
            else:
                iv = le64((inode['ino'] << 32) | lblk) + b'\x00' * 8
                pt = xts_decrypt(key.contents, iv, ct)
            out += pt
        return bytes(out[:size])

    # ---------------- directories ----------------
    def parse_inline_dir(self, inode):
        n = inode['raw']
        extra_units = inode['extra_units']
        ix_units = inode['ix_units']
        inline_len = 4 * (ADDRS_PER_INODE - extra_units - ix_units - 1)
        base = 360 + 4 * (extra_units + 1)
        if base + inline_len > 4052:
            inline_len = 4052 - base
        max_entry = inline_len * 8 // 153
        bm = (max_entry + 7) // 8
        reserved = inline_len - (19 * max_entry + bm)
        doff = base + bm + reserved
        foff = doff + 11 * max_entry
        ents = []
        for idx in range(max_entry):
            if not (n[base + (idx >> 3)] >> (idx & 7)) & 1:
                continue
            if doff + 11 * idx + 11 > foff:
                continue
            h, ci, nl, ft = struct.unpack_from('<IIHB', n, doff + 11 * idx)
            if ci == 0 or nl == 0 or nl > 255:
                continue
            if foff + 8 * idx + nl > base + inline_len:
                continue
            ents.append((n[foff + 8 * idx:foff + 8 * idx + nl], ci, ft))
        return ents

    def parse_dentry_block(self, blk):
        ents = []
        for idx in range(214):
            if not (blk[idx >> 3] >> (idx & 7)) & 1:
                continue
            off = 30 + 11 * idx
            h, ci, nl, ft = struct.unpack_from('<IIHB', blk, off)
            if ci == 0 or nl == 0 or nl > 255:
                continue
            if 2384 + 8 * idx + nl > BS:
                continue
            ents.append((blk[2384 + 8 * idx:2384 + 8 * idx + nl], ci, ft))
        return ents

    def read_dir(self, inode):
        if inode['inline'] & 0x04:
            return self.parse_inline_dir(inode)
        ents = []
        nblocks = (inode['size'] + BS - 1) // BS
        for blk in self.block_map(inode, nblocks):
            if blk:
                ents += self.parse_dentry_block(self.mblk(blk))
        return ents

    def list_dir(self, inode):
        mk, ctx = self.key_for(inode)
        out = []
        for raw, ci, ft in self.read_dir(inode):
            if raw in (b'.', b'..'):
                continue
            if mk is None:
                name = raw
            else:
                name = self.decrypt_name(inode, raw, mk)
                if name is None:
                    name = b'<undecryptable:' + raw.hex().encode() + b'>'
            out.append((name, ci, ft))
        return out


def path_join(parent, name):
    if parent == '/':
        return '/' + name
    return parent + '/' + name


def walk(fs, ino, path, max_depth=64, seen=None):
    if seen is None:
        seen = set()
    inode = fs.inode(ino)
    if inode is None:
        yield dict(path=path, ino=ino, type='missing')
        return
    if inode['mode'] & 0o170000 == 0o040000:
        if ino in seen:
            return
        seen.add(ino)
        yield dict(path=path, ino=ino, type='dir', size=inode['size'],
                   mode=inode['mode'])
        if max_depth <= 0:
            return
        for name, ci, ft in fs.list_dir(inode):
            nm = name.decode('utf-8', 'surrogateescape')
            yield from walk(fs, ci, path_join(path, nm), max_depth - 1, seen)
    elif inode['mode'] & 0o170000 == 0o120000:
        yield dict(path=path, ino=ino, type='symlink', size=inode['size'],
                   mode=inode['mode'])
    else:
        yield dict(path=path, ino=ino, type='file', size=inode['size'],
                   mode=inode['mode'], flags=inode['flags'],
                   ctx=(fs.context(inode) or (None,))[0].hex() if fs.context(inode) else None)


def extract(fs, ino, path, dest, manifest, seen=None):
    if seen is None:
        seen = set()
    inode = fs.inode(ino)
    if inode is None:
        manifest.write(json.dumps(dict(path=path, ino=ino, error='missing inode')) + '\n')
        return
    fmt = inode['mode'] & 0o170000
    if fmt == 0o040000:
        if ino in seen:
            return
        seen.add(ino)
        os.makedirs(dest, exist_ok=True)
        manifest.write(json.dumps(dict(path=path, ino=ino, type='dir',
                                        mode=oct(inode['mode'] & 0o7777))) + '\n')
        for name, ci, ft in fs.list_dir(inode):
            nm = name.decode('utf-8', 'surrogateescape')
            extract(fs, ci, path_join(path, nm), os.path.join(dest, nm), manifest, seen)
    elif fmt == 0o120000:
        try:
            target = fs.decrypt_content(inode, fs.key_for(inode)[0])
            target = target.split(b'\x00', 1)[0]
        except Exception as e:
            target = b'<error:%s>' % str(e).encode()
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        try:
            os.symlink(target, dest)
        except FileExistsError:
            os.unlink(dest)
            os.symlink(target, dest)
        manifest.write(json.dumps(dict(path=path, ino=ino, type='symlink',
                                        size=inode['size'],
                                        target=target.decode('utf-8', 'replace'))) + '\n')
    else:
        mk, ctx = fs.key_for(inode)
        if inode['flags'] & 0x04:
            manifest.write(json.dumps(dict(path=path, ino=ino, type='file',
                                            error='compressed', size=inode['size'])) + '\n')
            return
        try:
            data = fs.decrypt_content(inode, mk)
        except Exception as e:
            manifest.write(json.dumps(dict(path=path, ino=ino, type='file',
                                            error=str(e), size=inode['size'])) + '\n')
            return
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, 'wb') as f:
            f.write(data)
        sha = hashlib.sha256(data).hexdigest()
        manifest.write(json.dumps(dict(path=path, ino=ino, type='file',
                                        size=len(data), sha256=sha,
                                        mode=oct(inode['mode'] & 0o7777),
                                        ctx=ctx[0].hex() if ctx else None,
                                        key=('CE' if ctx and fs.mkeys[0].matches(ctx[0]) else
                                             'DE' if ctx and fs.mkeys[1].matches(ctx[0]) else
                                             None))) + '\n')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('action', choices=['tree', 'extract', 'verify'])
    ap.add_argument('ino', type=lambda x: int(x, 0))
    ap.add_argument('path')
    ap.add_argument('dest', nargs='?')
    args = ap.parse_args()
    fs = F2FS()
    if args.action == 'tree':
        for item in walk(fs, args.ino, args.path):
            print(json.dumps(item))
    elif args.action == 'extract':
        assert args.dest
        os.makedirs(args.dest, exist_ok=True)
        with open(os.path.join(args.dest, '.manifest.jsonl'), 'w') as m:
            extract(fs, args.ino, args.path, os.path.join(args.dest, 'root'), m)
    elif args.action == 'verify':
        inode = fs.inode(args.ino)
        mk, ctx = fs.key_for(inode)
        data = fs.decrypt_content(inode, mk)
        print(json.dumps(dict(ino=args.ino, size=len(data),
                              sha256=hashlib.sha256(data).hexdigest(),
                              ctx=ctx[0].hex() if ctx else None)))


if __name__ == '__main__':
    main()
