#!/usr/bin/env python3
"""Independent compatibility check for tools/crpx0_decrypt.py.

The fixtures are written by tools/go/crpx0fixtures (Go standard library,
own Fernet implementation from the spec, own RSA-4096 key pair), following
stage 3 L1335-1350. This script decrypts them with crpx0_decrypt.py, once with
the Fernet key and once through the RSA private key, and compares every output
with the plaintext SHA-256 recorded by the Go writer. A format misreading in
the decryptor would not be repeated by an independent writer, so a match here
confirms the format from two implementations.

Usage: crpx0_decrypt_crosscheck.py <go_fixture_dir> <workdir>   exit 0 = all match
"""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import crpx0_decrypt as D  # noqa: E402


def main(fix, work):
    manifest = json.load(open(os.path.join(fix, "manifest.json")))
    files = sorted(os.path.join(fix, "enc", m["name"] + ".crpx0") for m in manifest)
    key = open(os.path.join(fix, "fernet.key")).read().strip()
    results = {}
    for mode, args in (("key", ["--key", key]), ("rsa", ["--rsa-private", os.path.join(fix, "rsa_private.pem")])):
        out = os.path.join(work, "out_" + mode)
        rc = D.main(["decrypt", *args, "--out", out, *files])
        ok = rc == 0 and all(
            hashlib.sha256(open(os.path.join(out, m["name"]), "rb").read()).hexdigest() == m["sha256"]
            for m in manifest)
        results[mode] = ok
        print(("PASS " if ok else "FAIL ") + f"Go-written fixtures decrypted via {mode}: {len(manifest)} files byte-identical")
    sal = os.path.join(work, "out_salvage")
    D.main(["salvage", "--out", sal, *files])
    big = [m for m in manifest if m["size"] > 1024 * 1024]
    results["salvage_sizes"] = all(os.path.getsize(os.path.join(sal, m["name"] + ".partial")) == m["size"] for m in big)
    print(("PASS " if results["salvage_sizes"] else "FAIL ") + f"salvage keeps exact size for {len(big)} files > 1 MiB")
    summary = {"writer": "tools/go/crpx0fixtures (Go stdlib)", "files": len(manifest),
               "sizes": [m["size"] for m in manifest], "checks": results, "all_passed": all(results.values())}
    json.dump(summary, open(os.path.join(work, "crosscheck_summary.json"), "w"), indent=1)
    print("ALL PASSED" if summary["all_passed"] else "SOME CHECKS FAILED")
    return 0 if summary["all_passed"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
