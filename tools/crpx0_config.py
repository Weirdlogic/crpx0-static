#!/usr/bin/env python3
"""CRPx0 stage 3 (Python ransomware source) -> configuration, offline.

The stage 3 source is parsed with ast only; it is never compiled or run.

Layer 4 (_init_crypto, stage 3 line 1573):
  XOR_KEY = Fernet(AES_KEY_B64).decrypt(ENCRYPTED_XOR_KEY)
  dx(list) = bytes(b ^ XOR_KEY[i % len(XOR_KEY)])        (line 64)
Every dx() argument in the file is decoded: inline int lists, and lists bound
to a local name that is then passed to dx (check_debugger, patch_amsi).
In this build the Fernet-decrypted key equals the plaintext XOR_KEY literal;
the tool reports whether that holds.

Usage: crpx0_config.py <stage3.py> <out.json> [--notes DIR] [--wallpaper OUT.png]
out.json holds raw (undefanged) values and stays in quarantine; the report
publishes defanged copies only.
"""
import argparse
import ast
import base64
import hashlib
import json
import os

from cryptography.fernet import Fernet

LITERALS = [
    "OPERATION_ID", "PARENT_ID", "RSA_PUBLIC_KEY", "XOR_KEY", "AMSI_PATCH_KEY",
    "ETW_PATCH_KEY", "AES_KEY_B64", "ENCRYPTED_XOR_KEY", "RECOVERY_FILE",
    "RECOVERY_FILE_HTML", "SCAN_REPORT", "ENCRYPTED_EXT", "DECOY_NAME",
    "AFFILIATE_ID", "C2_AUTH_TOKEN", "SELF_EXCLUDE_TAG", "FILE_EXTENSIONS",
    "EXCLUDE_DIRS", "KILL_AV_PROCESSES", "KILL_AV_SERVICES",
]


def int_list(node):
    if isinstance(node, ast.List) and node.elts and all(
            isinstance(e, ast.Constant) and isinstance(e.value, int) for e in node.elts):
        return [e.value for e in node.elts]
    return None


def dx_calls(tree):
    """Yield (lineno, function, target, values) for every dx(...) call."""
    funcs = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]

    def owner(line):
        best = None
        for f in funcs:
            if f.lineno <= line <= f.end_lineno and (best is None or f.lineno > best.lineno):
                best = f
        return best

    targets = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name):
            for c in ast.walk(n.value):
                targets[id(c)] = n.targets[0].id
    for c in ast.walk(tree):
        if not (isinstance(c, ast.Call) and getattr(c.func, "id", None) == "dx" and c.args):
            continue
        f = owner(c.lineno)
        arg = c.args[0]
        vals = int_list(arg)
        if vals is None and isinstance(arg, ast.Name) and f is not None:
            for n in ast.walk(f):  # resolve a local list bound earlier in the same function
                if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", None) == arg.id:
                    vals = int_list(n.value)
        if vals is not None:
            yield c.lineno, f.name if f else "<module>", targets.get(id(c)), vals


def extract(src):
    tree = ast.parse(src)
    lit = {}
    wall = None
    for n in tree.body:
        if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name):
            if n.targets[0].id in LITERALS:
                lit[n.targets[0].id] = ast.literal_eval(n.value)
            elif n.targets[0].id == "BACKGROUND_B64":
                wall = base64.b64decode(n.value.value)
    xor_key = Fernet(lit["AES_KEY_B64"]).decrypt(lit["ENCRYPTED_XOR_KEY"])
    tok = base64.urlsafe_b64decode(lit["ENCRYPTED_XOR_KEY"])
    fernet_ts = int.from_bytes(tok[1:9], "big")
    decoded = []
    for line, fn, tgt, vals in sorted(dx_calls(tree)):
        text = bytes(b ^ xor_key[i % len(xor_key)] for i, b in enumerate(vals))
        decoded.append({"line": line, "function": fn, "target": tgt, "len": len(vals),
                        "text": text.decode("utf-8", "replace")})
    return lit, xor_key, fernet_ts, decoded, wall


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("stage3")
    ap.add_argument("out")
    ap.add_argument("--notes")
    ap.add_argument("--wallpaper")
    a = ap.parse_args()
    src = open(a.stage3, encoding="utf-8").read()
    lit, xk, ts, dec, wall = extract(src)
    by_tgt = {d["target"]: d["text"] for d in dec if d["target"]}
    cfg = {
        "stage3_sha256": hashlib.sha256(src.encode("utf-8")).hexdigest(),
        "xor_key_fernet_decrypted": xk.decode("latin-1"),
        "xor_key_equals_plaintext_literal": xk == lit["XOR_KEY"],
        "encrypted_xor_key_fernet_timestamp": ts,
        "remote_urls": [u.strip() for u in by_tgt.get("REMOTE_URLS", "").split("|") if u.strip()],
        "c2_auth_token": by_tgt.get("C2_AUTH_TOKEN"),
        "wallpaper_png": {"size": len(wall), "sha256": hashlib.sha256(wall).hexdigest()} if wall else None,
        "literals": lit,
        "dx_strings": dec,
    }
    json.dump(cfg, open(a.out, "w"), indent=1, ensure_ascii=False,
              default=lambda o: o.decode("latin-1") if isinstance(o, bytes) else str(o))
    if a.notes:
        os.makedirs(a.notes, exist_ok=True)
        for t, fn in (("RECOVERY_NOTE_TEMPLATE", "note.txt"), ("RECOVERY_NOTE_TEMPLATE_HTML", "note.html.txt")):
            if t in by_tgt:
                open(os.path.join(a.notes, fn), "w", encoding="utf-8").write(by_tgt[t])
    if a.wallpaper and wall:
        open(a.wallpaper, "wb").write(wall)
    print(f"xor key {len(xk)} bytes (= literal: {xk == lit['XOR_KEY']}, fernet ts {ts}); "
          f"{len(dec)} dx strings; {len(cfg['remote_urls'])} remote urls; wallpaper {len(wall) if wall else 0} bytes")
