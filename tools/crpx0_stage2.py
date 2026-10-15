#!/usr/bin/env python3
"""CRPx0 stage 2 (MinGW Python-runtime installer) -> stage 3 Python source, offline.

Stage 2 (sha256 5856f684...) carries three XOR-encoded regions in .data:
  * key 0xD3: installer config (python.org embed URLs, get-pip, pip packages,
    file names) at 0x40b020..0x40b260, and the API/DLL name table used by the
    resolver FUN_0040153b at 0x7abde0..0x7ac0a0 (decoder FUN_004014f0 / inline).
  * key 0xD6: the dropped bootstrap script (written as sys_service.py):
    0x40b260..0x7abde0. It holds one base64(zlib(source)) literal and runs
    exec(compile(zlib.decompress(b64decode(blob)), __file__, 'exec')).

This tool only decodes. It never compiles or executes the recovered Python.

Usage: crpx0_stage2.py <stage2.bin> <outdir>
  writes outdir/stage2_strings.txt, outdir/bootstrap.py.txt (blob elided),
  and prints the stage 3 sha256; stage 3 bytes go to outdir/stage3.py.txt
"""
import base64
import hashlib
import os
import re
import struct
import sys
import zlib

BASE = 0x400000  # EXE builds; DLL builds use their own base (see section())


def va2off(pe, va):
    e = struct.unpack_from("<I", pe, 0x3C)[0]
    nsec = struct.unpack_from("<H", pe, e + 6)[0]
    optsz = struct.unpack_from("<H", pe, e + 20)[0]
    so = e + 24 + optsz
    rva = va - BASE
    for i in range(nsec):
        vs, sva, rs, ro = struct.unpack_from("<IIII", pe, so + 40 * i + 8)
        if sva <= rva < sva + max(vs, rs):
            return ro + rva - sva
    raise ValueError(hex(va))


def xr(pe, start, end, key):
    return bytes(c ^ key for c in pe[va2off(pe, start):va2off(pe, end)])


def strings(blob, base):
    return [(base + m.start(), m.group().decode()) for m in re.finditer(rb"[\x20-\x7e]{4,}", blob)]


def section(pe, name):
    e = struct.unpack_from("<I", pe, 0x3C)[0]
    nsec = struct.unpack_from("<H", pe, e + 6)[0]
    optsz = struct.unpack_from("<H", pe, e + 20)[0]
    base = struct.unpack_from("<I", pe, e + 24 + 28)[0]
    so = e + 24 + optsz
    for i in range(nsec):
        n, vs, va, rs, ro = struct.unpack_from("<8sIIII", pe, so + 40 * i)
        if n.rstrip(b"\0") == name:
            return base + va, pe[ro:ro + rs]
    raise ValueError(name)


def find_key(data, plain):
    """Single-byte XOR key recovered by known plaintext (keys differ per build)."""
    for k in range(256):
        if plain in data.translate(bytes(c ^ k for c in range(256))):
            return k
    raise ValueError(f"no key for {plain!r}")


def decode(pe):
    """Fixed VAs and keys above are for 28685dff. Every build re-keys both XOR
    layers (seen: D3/D6, 77/A1, 3C/FB), so keys are recovered by known
    plaintext and regions are located by content:
      config key    <- 'https://www.python.org/ftp/python/' (embed URL)
      bootstrap key <- 'import sys, os' (first line of sys_service.py)
    The bootstrap ends with the exec(compile(...), globals()) line; its length
    equals the WriteFile size stage 2 stores next to it (0x3A0B78 here)."""
    dva, data = section(pe, b".data")
    kc = find_key(data, b"https://www.python.org/ftp/python/")
    kb = find_key(data, b"import sys, os")
    db = data.translate(bytes(c ^ kb for c in range(256)))
    i = db.find(b"import sys, os")
    mb = re.compile(rb"= '([A-Za-z0-9+/=]{1000,})'").search(db, i)
    end = b"), globals())\n"
    j = db.find(end, mb.end()) + len(end)
    boot = db[i:j]
    dc = data.translate(bytes(c ^ kc for c in range(256)))
    cfg = strings(dc[:i], dva)
    k = dc.find(b"kernel32.dll", j)
    api = strings(dc[k:k + 0x2C0], dva + k)
    blob = mb.group(1)
    stage3 = zlib.decompress(base64.b64decode(blob))
    elided = boot[: mb.start(1) - i] + b"<BLOB %d bytes>" % len(blob) + boot[mb.end(1) - i:]
    return cfg, api, elided, blob, stage3, len(boot), (kc, kb)


if __name__ == "__main__":
    pe = open(sys.argv[1], "rb").read()
    out = sys.argv[2]
    os.makedirs(out, exist_ok=True)
    cfg, api, boot, blob, s3, blen, keys = decode(pe)
    with open(os.path.join(out, "stage2_strings.txt"), "w") as f:
        f.write(f"# key {keys[0]:#04x}, installer config\n")
        f.writelines(f"{a:#x}\t{s}\n" for a, s in cfg)
        f.write(f"# key {keys[0]:#04x}, API resolver table\n")
        f.writelines(f"{a:#x}\t{s}\n" for a, s in api)
    open(os.path.join(out, "bootstrap.py.txt"), "wb").write(boot)
    open(os.path.join(out, "stage3.py.txt"), "wb").write(s3)
    print(f"keys config {keys[0]:#04x} bootstrap {keys[1]:#04x}; bootstrap script {blen} bytes")
    print(f"blob {len(blob)} b64 chars, sha256(blob) {hashlib.sha256(blob).hexdigest()}")
    print(f"stage3 {len(s3)} bytes sha256 {hashlib.sha256(s3).hexdigest()}")
