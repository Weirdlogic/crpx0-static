#!/usr/bin/env python3
"""Extract a quarantined MalwareBazaar sample for STATIC analysis only.

    python3 tools/unzip-sample.py <sha256>

Decrypts samples/<sha256>/<sha256>.zip (WinZip AES, password "infected") and
writes samples/<sha256>/sample.bin with mode 0400 (read-only, never executable).
The plaintext SHA-256 must equal the folder name or nothing is written.
Uses only the stdlib plus `cryptography` (already on this system).
"""
import hashlib
import hmac
import os
import struct
import sys
import zipfile
import zlib
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT = Path(__file__).resolve().parent.parent
PASSWORD = b"infected"
KEY_LEN = {1: 16, 2: 24, 3: 32}  # AES-128/192/256


def aes_extra(extra):
    i = 0
    while i + 4 <= len(extra):
        hid, size = struct.unpack_from("<HH", extra, i)
        if hid == 0x9901:
            _ver, vendor, strength, method = struct.unpack_from("<H2sBH", extra, i + 4)
            if vendor != b"AE":
                break
            return strength, method
        i += 4 + size
    sys.exit("not a WinZip AES entry")


def decrypt(raw, strength):
    klen = KEY_LEN[strength]
    salt, pv = raw[:klen // 2], raw[klen // 2:klen // 2 + 2]
    body, mac = raw[klen // 2 + 2:-10], raw[-10:]
    km = hashlib.pbkdf2_hmac("sha1", PASSWORD, salt, 1000, 2 * klen + 2)
    aes_key, mac_key, verifier = km[:klen], km[klen:2 * klen], km[2 * klen:]
    if verifier != pv:
        sys.exit("wrong password")
    if not hmac.compare_digest(hmac.new(mac_key, body, hashlib.sha1).digest()[:10], mac):
        sys.exit("HMAC check failed: archive corrupt or tampered")
    # WinZip AES-CTR uses a little-endian counter starting at 1.
    ecb = Cipher(algorithms.AES(aes_key), modes.ECB()).encryptor()
    n = (len(body) + 15) // 16
    stream = ecb.update(b"".join((i + 1).to_bytes(16, "little") for i in range(n)))
    return bytes(a ^ b for a, b in zip(body, stream))


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sha = sys.argv[1].lower()
    d = ROOT / "samples" / sha
    out = d / "sample.bin"
    if out.exists():
        print(f"already extracted: {out.relative_to(ROOT)}")
        return
    with zipfile.ZipFile(d / f"{sha}.zip") as z, open(d / f"{sha}.zip", "rb") as f:
        info = z.infolist()[0]
        strength, method = aes_extra(info.extra)
        f.seek(info.header_offset)
        hdr = f.read(30)
        n, m = struct.unpack_from("<HH", hdr, 26)
        f.seek(info.header_offset + 30 + n + m)
        data = decrypt(f.read(info.compress_size), strength)
    if method == zipfile.ZIP_DEFLATED:
        data = zlib.decompress(data, -15)
    elif method != zipfile.ZIP_STORED:
        sys.exit(f"unsupported inner compression {method}")
    got = hashlib.sha256(data).hexdigest()
    if got != sha:
        sys.exit(f"SHA-256 mismatch: {got}")
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    print(f"extracted {info.filename!r} -> {out.relative_to(ROOT)} ({len(data)} bytes, sha256 verified, mode 0400)")


if __name__ == "__main__":
    main()
