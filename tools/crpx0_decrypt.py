#!/usr/bin/env python3
"""Clean-room recovery tool for CRPx0 (.crpx0) files. Written from the static
analysis of stage 3 (stage2_encrypt, line 1256); it shares no code with the
malware and never runs it.

File format (all 7 builds of 2026-08-02):
  u32le  rsa_len   (512 for the RSA-4096 key)
  bytes  rsa_blob  RSA-OAEP(SHA-256) of the per-run Fernet key (operator key)
  u64le  tok_len
  bytes  token     Fernet token = Fernet(key).encrypt(first 1 MiB of the file)
  bytes  tail      the rest of the original file, NOT encrypted
One Fernet key per run (Fernet.generate_key -> os.urandom) covers every file
on that host. Without the key or the operator's RSA private key the first
MiB cannot be decrypted; the tail is always recoverable.

Commands (outputs go to a separate directory; inputs are never modified):
  inspect  FILE...                     header, sizes, encryption time (Fernet ts)
  keyhunt  --check FILE.crpx0 [--any] SRC...
                                       find "decryption_key" values in captures/logs
                                       (the malware POSTs the key in JSON over plain
                                       HTTP); --any tests every key-shaped token, for
                                       memory images, pagefile.sys, hiberfil.sys.
                                       Each candidate is verified against FILE's HMAC.
  decrypt  --key KEY | --rsa-private PEM  --out DIR  FILE...
  salvage  --out DIR FILE...           write the plaintext tail (+ zeroed first MiB)

Exit status is non-zero if any file fails.
"""
import argparse
import base64
import datetime as dt
import hashlib
import hmac
import os
import re
import struct
import sys

CHUNK = 1024 * 1024
EXT = ".crpx0"


class Crpx0File:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            raw = f.read()
        if len(raw) < 4:
            raise ValueError("too short")
        self.rsa_len = struct.unpack_from("<I", raw, 0)[0]
        if not 0 < self.rsa_len <= 10000 or len(raw) < 12 + self.rsa_len:
            raise ValueError(f"bad rsa_len {self.rsa_len}")
        self.rsa_blob = raw[4:4 + self.rsa_len]
        o = 4 + self.rsa_len
        self.tok_len = struct.unpack_from("<Q", raw, o)[0]
        o += 8
        self.token = base64.urlsafe_b64decode(raw[o:o + self.tok_len]) if self.tok_len else b""
        self.token_b64 = raw[o:o + self.tok_len]
        if len(self.token_b64) != self.tok_len or not self.token or self.token[0] != 0x80:
            raise ValueError("Fernet token missing or truncated")
        self.tail = raw[o + self.tok_len:]
        self.timestamp = struct.unpack(">Q", self.token[1:9])[0]

    # Fernet, implemented from the spec so the check is independent of the library
    def hmac_ok(self, key_b64):
        try:
            key = base64.urlsafe_b64decode(key_b64)
        except Exception:
            return False
        if len(key) != 32:
            return False
        tag = hmac.new(key[:16], self.token[:-32], hashlib.sha256).digest()
        return hmac.compare_digest(tag, self.token[-32:])

    def head_plain(self, key_b64):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        if not self.hmac_ok(key_b64):
            raise ValueError("key does not match this file (HMAC check failed)")
        key = base64.urlsafe_b64decode(key_b64)
        iv, ct = self.token[9:25], self.token[25:-32]
        d = Cipher(algorithms.AES(key[16:]), modes.CBC(iv)).decryptor()
        pt = d.update(ct) + d.finalize()
        pad = pt[-1]
        if not 1 <= pad <= 16 or pt[-pad:] != bytes([pad]) * pad:
            raise ValueError("bad padding")
        return pt[:-pad]


def out_path(outdir, src):
    name = os.path.basename(src)
    name = name[: -len(EXT)] if name.endswith(EXT) else name + ".recovered"
    p = os.path.join(outdir, name)
    if os.path.exists(p):
        raise FileExistsError(p)
    return p


def rsa_unwrap(pem_path, blob):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    priv = serialization.load_pem_private_key(open(pem_path, "rb").read(), password=None)
    return priv.decrypt(blob, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                           algorithm=hashes.SHA256(), label=None))


KEY_RE = re.compile(rb'"decryption_key"\s*:\s*"([A-Za-z0-9_\-]{43}=)"')
# any free-standing 44-char urlsafe-base64 Fernet key (32 bytes -> 43 chars + '=')
ANY_RE = re.compile(rb'(?<![A-Za-z0-9_\-])([A-Za-z0-9_\-]{42}[AEIMQUYcgkosw048]=)(?![A-Za-z0-9_\-=])')
CHUNK_SCAN = 64 * 1024 * 1024


def candidates(path, any_key):
    """Stream a file of any size (PCAP, proxy log, memory image, pagefile.sys,
    hiberfil, disk image) and yield candidate keys. With any_key, every
    free-standing 44-char key-shaped token is a candidate, not only the
    JSON field the malware sends."""
    rx = ANY_RE if any_key else KEY_RE
    with open(path, "rb") as f:
        prev = b""
        while True:
            buf = f.read(CHUNK_SCAN)
            if not buf:
                break
            data = prev + buf
            for m in rx.finditer(data):
                yield m.group(1)
            prev = data[-128:]


def cmd_inspect(a):
    bad = 0
    for p in a.files:
        try:
            c = Crpx0File(p)
            when = dt.datetime.fromtimestamp(c.timestamp, dt.timezone.utc).isoformat()
            print(f"{p}\n  rsa_len {c.rsa_len}  rsa_blob sha256 {hashlib.sha256(c.rsa_blob).hexdigest()[:16]}"
                  f"\n  token {c.tok_len} b64 chars ({len(c.token) - 57} ciphertext bytes)  encrypted at {when}"
                  f"\n  plaintext tail {len(c.tail)} bytes")
        except Exception as e:
            bad += 1
            print(f"{p}: not a CRPx0 file ({e})")
    return bad


def cmd_keyhunt(a):
    c = Crpx0File(a.check)
    found, tested = {}, 0
    for src in a.sources:
        for k in candidates(src, a.any):
            tested += 1
            if k not in found:
                found[k] = (src, c.hmac_ok(k))
    good = [k for k, (_, ok) in found.items() if ok]
    for k, (src, ok) in found.items():
        if ok or not a.any:
            print(f"{'MATCH' if ok else 'no match'}  {k.decode()}  (from {src})")
    print(f"{tested} candidate(s), {len(found)} distinct, {len(good)} verified against {a.check}")
    return 0 if good else 1


def cmd_decrypt(a):
    bad = 0
    os.makedirs(a.out, exist_ok=True)
    for p in a.files:
        try:
            c = Crpx0File(p)
            key = a.key.encode() if a.key else rsa_unwrap(a.rsa_private, c.rsa_blob)
            head = c.head_plain(key)
            dst = out_path(a.out, p)
            with open(dst, "wb") as f:
                f.write(head + c.tail)
            print(f"ok  {p} -> {dst} ({len(head) + len(c.tail)} bytes)")
        except Exception as e:
            bad += 1
            print(f"FAIL {p}: {e}")
    return bad


def cmd_salvage(a):
    bad = 0
    os.makedirs(a.out, exist_ok=True)
    for p in a.files:
        try:
            c = Crpx0File(p)
            dst = out_path(a.out, p) + ".partial"
            # the encrypted head was exactly min(CHUNK, original size) bytes;
            # Fernet ciphertext length = 16*(n//16 + 1), so n is known to within 16 bytes
            n_max = len(c.token) - 57 - 1
            head_len = CHUNK if c.tail else n_max
            with open(dst, "wb") as f:
                f.write(b"\0" * head_len + c.tail)
            print(f"ok  {p} -> {dst} (first {head_len} bytes zeroed, {len(c.tail)} bytes recovered)")
        except Exception as e:
            bad += 1
            print(f"FAIL {p}: {e}")
    return bad


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest="cmd", required=True)
    s = sp.add_parser("inspect"); s.add_argument("files", nargs="+")
    s = sp.add_parser("keyhunt"); s.add_argument("--check", required=True)
    s.add_argument("--any", action="store_true", help="test every 44-char key-shaped token (memory images, pagefile)")
    s.add_argument("sources", nargs="+")
    s = sp.add_parser("decrypt"); g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--key"); g.add_argument("--rsa-private")
    s.add_argument("--out", required=True); s.add_argument("files", nargs="+")
    s = sp.add_parser("salvage"); s.add_argument("--out", required=True); s.add_argument("files", nargs="+")
    a = ap.parse_args(argv)
    return {"inspect": cmd_inspect, "keyhunt": cmd_keyhunt, "decrypt": cmd_decrypt, "salvage": cmd_salvage}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
