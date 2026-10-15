#!/usr/bin/env python3
"""Validation of tools/crpx0_decrypt.py on synthetic files only.

Fixtures are written in the CRPx0 on-disk format (see crpx0_decrypt.py) with a
Fernet key and an RSA-4096 key pair generated here, so no operator key, no
victim file and no sample code is involved. The fixture writer only turns
given bytes into one output file; it does not walk, overwrite or delete.

Checks: decrypt with the Fernet key, decrypt via our RSA private key, keyhunt
in a synthetic proxy log (true key among decoys), salvage of the plaintext
tail, wrong key and tampered token rejected, sizes around the 1 MiB boundary.

Usage: crpx0_decrypt_test.py <empty_workdir>      exit 0 = all checks passed
"""
import hashlib
import json
import os
import random
import sys

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import crpx0_decrypt as D  # noqa: E402

MiB = 1024 * 1024
SIZES = [0, 1, 15, 16, 17, 4096, MiB - 1, MiB, MiB + 1, 3 * MiB + 12345]


def write_fixture(path, plain, fkey, pub):
    """CRPx0 layout: u32 rsa_len | rsa_blob | u64 tok_len | Fernet(head) | tail."""
    blob = pub.encrypt(fkey, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    tok = Fernet(fkey).encrypt(plain[:MiB])
    with open(path, "wb") as f:
        f.write(len(blob).to_bytes(4, "little") + blob + len(tok).to_bytes(8, "little") + tok + plain[MiB:])


def main(work):
    os.makedirs(work, exist_ok=False)
    rnd = random.Random(20261015)
    priv = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    pem = os.path.join(work, "test_private.pem")
    open(pem, "wb").write(priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption()))
    fkey = Fernet.generate_key()
    enc_dir, plain_dir = os.path.join(work, "enc"), os.path.join(work, "plain")
    os.makedirs(enc_dir); os.makedirs(plain_dir)
    originals = {}
    for n in SIZES:
        data = rnd.randbytes(n)
        name = f"synthetic_{n}.bin"
        open(os.path.join(plain_dir, name), "wb").write(data)
        write_fixture(os.path.join(enc_dir, name + ".crpx0"), data, fkey, priv.public_key())
        originals[name] = data
    files = sorted(os.path.join(enc_dir, f) for f in os.listdir(enc_dir))
    results = {}

    def check(name, cond):
        results[name] = bool(cond)
        print(("PASS " if cond else "FAIL ") + name)

    check("inspect parses all fixtures", D.main(["inspect", *files]) == 0)

    # synthetic proxy log: the JSON body the malware POSTs, plus decoys
    log = os.path.join(work, "proxy_body.log")
    with open(log, "w") as f:
        for _ in range(3):
            f.write(json.dumps({"status": "key_handshake", "decryption_key": Fernet.generate_key().decode()}) + "\n")
        f.write("POST /relay.php HTTP/1.1\r\nContent-Type: application/json\r\n\r\n"
                + json.dumps({"operation_id": "OP_TEST", "status": "key_handshake",
                              "decryption_key": fkey.decode(), "pre_encrypt": "1"}) + "\n")
    check("keyhunt verifies the true key among decoys", D.main(["keyhunt", "--check", files[0], log]) == 0)

    # synthetic "memory image": 48 MiB of random bytes spanning a scan-chunk
    # boundary, with key-shaped decoys and the real key as a bare ASCII string
    mem = os.path.join(work, "synthetic_memory.img")
    with open(mem, "wb") as f:
        for _ in range(3):
            f.write(rnd.randbytes(16 * MiB))
            f.write(b"\0" + Fernet.generate_key() + b"\0")
        f.write(rnd.randbytes(5 * MiB) + b"\x00\x00" + fkey + b"\x00" + rnd.randbytes(MiB))
    D.CHUNK_SCAN = 8 * MiB   # force several chunk boundaries in the test
    check("keyhunt --any finds the bare key in a memory-style image",
          D.main(["keyhunt", "--check", files[0], "--any", mem]) == 0)
    nokey = os.path.join(work, "synthetic_memory_nokey.img")
    open(nokey, "wb").write(rnd.randbytes(MiB) + b"\0" + Fernet.generate_key() + b"\0")
    check("keyhunt --any rejects a memory image without the key",
          D.main(["keyhunt", "--check", files[0], "--any", nokey]) == 1)

    out1 = os.path.join(work, "out_key")
    check("decrypt --key: no failures", D.main(["decrypt", "--key", fkey.decode(), "--out", out1, *files]) == 0)
    check("decrypt --key: byte-identical to originals",
          all(open(os.path.join(out1, n), "rb").read() == d for n, d in originals.items()))

    out2 = os.path.join(work, "out_rsa")
    check("decrypt --rsa-private: no failures", D.main(["decrypt", "--rsa-private", pem, "--out", out2, *files]) == 0)
    check("decrypt --rsa-private: byte-identical",
          all(open(os.path.join(out2, n), "rb").read() == d for n, d in originals.items()))

    out3 = os.path.join(work, "out_salvage")
    D.main(["salvage", "--out", out3, *files])
    check("salvage: tail recovered exactly for files > 1 MiB",
          all(open(os.path.join(out3, n + ".partial"), "rb").read()[MiB:] == d[MiB:]
              for n, d in originals.items() if len(d) > MiB))
    check("salvage: size exact for files > 1 MiB",
          all(os.path.getsize(os.path.join(out3, n + ".partial")) == len(d)
              for n, d in originals.items() if len(d) > MiB))

    out4 = os.path.join(work, "out_wrong")
    check("wrong key rejected for every file",
          D.main(["decrypt", "--key", Fernet.generate_key().decode(), "--out", out4, *files]) == len(files))
    check("wrong key wrote nothing", not os.listdir(out4))

    t = os.path.join(work, "tampered.bin.crpx0")
    raw = bytearray(open(files[-1], "rb").read()); raw[4 + 512 + 8 + 100] ^= 0x01
    open(t, "wb").write(raw)
    check("tampered token rejected", D.main(["decrypt", "--key", fkey.decode(), "--out", os.path.join(work, "o5"), t]) == 1)
    check("input files untouched",
          all(os.path.exists(f) for f in files))

    summary = {"sizes": SIZES, "checks": results, "all_passed": all(results.values()),
               "note": "synthetic fixtures, keys generated by the test; no operator key involved"}
    json.dump(summary, open(os.path.join(work, "summary.json"), "w"), indent=1)
    print("ALL PASSED" if summary["all_passed"] else "SOME CHECKS FAILED")
    return 0 if summary["all_passed"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
