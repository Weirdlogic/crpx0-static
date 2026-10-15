#!/usr/bin/env python3
"""CRPx0 stage 1 (MinGW dropper stub) -> stage 2, reimplemented offline.

Decoder at 0x401566 (sample 28685dff...c11):
  k1 = 64 bytes @0x7b3840 ^ byte @0x7b38c0
  k2 = 64 bytes @0x7b3880 ^ byte @0x7b38c1
  n  = dword  @0x7b3820
  for i in range(n): b = data[i] ^ k2[i&63]; b = ror8(b,r); b = ~b; b ^= k1[i&63]   (r = 1 here)
  data = bytes @0x403020
Each build re-generates the stub (junk arithmetic, different .text hash) and
DLL builds use another image base, so the operands are located by opcode
pattern in .text rather than hard-coded:
  movzx eax, byte [eax+K]      0F B6 80 K     -> K2 (first use), K1 (second)
  movzx eax, byte [X]; xor     0F B6 05 X 31 C2 -> X1, X2 (in key order)
  mov eax, [N]; cmp [ebp+x]    A1 N 39 45     -> size
  add eax, D                   05 D (most frequent) -> data
  shr al, r  (C0 E8 r / D0 E8) between the two key loads -> ror r
The rotate amount is chosen per build (1, 2, 4, 6, 7 seen in 7 builds); NOT
commutes with rotation, so the op order inside the loop does not matter.
The stub writes the result to %LOCALAPPDATA%\\index.dll and runs it with
CreateProcessA(..., CREATE_NO_WINDOW) (0x4016db). Nothing here executes it.

Usage: crpx0_stage1.py <stage1.bin> <out.bin>
"""
import collections
import hashlib
import re
import struct
import sys


def va2off(pe, va):
    e = struct.unpack_from("<I", pe, 0x3C)[0]
    nsec = struct.unpack_from("<H", pe, e + 6)[0]
    optsz = struct.unpack_from("<H", pe, e + 20)[0]
    base = struct.unpack_from("<I", pe, e + 24 + 28)[0]
    rva = va - base
    so = e + 24 + optsz
    for i in range(nsec):
        vs, sva, rs, ro = struct.unpack_from("<IIII", pe, so + 40 * i + 8)
        if sva <= rva < sva + max(vs, rs):
            return ro + rva - sva
    raise ValueError(hex(va))


def locate(pe):
    e = struct.unpack_from("<I", pe, 0x3C)[0]
    optsz = struct.unpack_from("<H", pe, e + 20)[0]
    so = e + 24 + optsz
    rs, ro = struct.unpack_from("<II", pe, so + 16)  # first section = .text
    text = pe[ro:ro + rs]
    imm = lambda pat: [struct.unpack("<I", m.group(1))[0] for m in re.finditer(pat, text, re.S)]
    karr = imm(rb"\x0f\xb6\x80(.{4})")
    xb = imm(rb"\x0f\xb6\x05(.{4})\x31\xc2")
    size = imm(rb"\xa1(.{4})\x39\x45")
    data = collections.Counter(imm(rb"\x05(.{4})")).most_common(1)[0][0]
    assert len(karr) == 2 and len(xb) == 2 and len(size) == 1, (karr, xb, size)
    k2a, k1a = karr                       # k2 is applied first, k1 last
    x1a, x2a = sorted(xb)                 # x1 pairs with the lower key array (k1)
    assert k1a < k2a and x2a == x1a + 1   # layout seen in all 7 builds
    p = [m.start() for m in re.finditer(rb"\x0f\xb6\x80", text)]
    seg = text[p[0]:p[1]]
    m = re.search(rb"\xc0\xe8(.)|\xd0\xe8", seg, re.S)
    rot = m.group(1)[0] if m.group(1) else 1
    assert b"\xf7\xd0" in seg  # not eax
    return {"k1": k1a, "x1": x1a, "k2": k2a, "x2": x2a, "size": size[0], "data": data, "ror": rot}


def decode(pe):
    a = locate(pe)
    k1 = bytes(x ^ pe[va2off(pe, a["x1"])] for x in pe[va2off(pe, a["k1"]):][:64])
    k2 = bytes(x ^ pe[va2off(pe, a["x2"])] for x in pe[va2off(pe, a["k2"]):][:64])
    n = struct.unpack_from("<I", pe, va2off(pe, a["size"]))[0]
    src = pe[va2off(pe, a["data"]):][:n]
    r = a["ror"]
    out = bytearray(n)
    for i, b in enumerate(src):
        b ^= k2[i & 63]
        b = ((b >> r) | (b << (8 - r))) & 0xFF
        b ^= 0xFF
        out[i] = b ^ k1[i & 63]
    return bytes(out), n, k1, k2


if __name__ == "__main__":
    pe = open(sys.argv[1], "rb").read()
    out, n, k1, k2 = decode(pe)
    open(sys.argv[2], "wb").write(out)
    print(f"size {n}  head {out[:2]!r}  sha256 {hashlib.sha256(out).hexdigest()}")
    print(f"k1 {k1.hex()}\nk2 {k2.hex()}")
