#!/usr/bin/env python3
"""Run the CRPx0 static pipeline (stage1 -> stage2 -> stage3 -> config) over
several quarantined samples and tabulate what changes between builds.
Decoded stages are written next to each sample as stageN_<sha16>.bin (0400).
Raw config stays in samples/<sha>/cfg/; the summary written here holds hashes
and defanged values only. Nothing is executed.

Usage: crpx0_crosssample.py <out.json> <sha256> [<sha256> ...]
"""
import hashlib, json, os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import crpx0_stage1, crpx0_stage2, crpx0_config  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
H = lambda b: hashlib.sha256(b).hexdigest()


def defang(u):
    return u.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")


def keep(folder, n, data):
    p = os.path.join(folder, f"stage{n}_{H(data)[:16]}.bin")
    if not os.path.exists(p):
        open(p, "wb").write(data); os.chmod(p, 0o400)
    return p


def pe_info(b):
    e = struct.unpack_from("<I", b, 0x3C)[0]
    ch = struct.unpack_from("<H", b, e + 22)[0]
    return {"ts": struct.unpack_from("<I", b, e + 8)[0], "dll": bool(ch & 0x2000)}


rows = []
for sha in sys.argv[2:]:
    d = os.path.join(ROOT, "samples", sha)
    s1 = open(os.path.join(d, "sample.bin"), "rb").read()
    assert H(s1) == sha
    s2, *_ = crpx0_stage1.decode(s1)
    keep(d, 2, s2)
    cfg_s, api, boot, blob, s3, blen, k2 = crpx0_stage2.decode(s2)
    r1 = crpx0_stage1.locate(s1)["ror"]
    keep(d, 3, s3)
    lit, xk, ts, dec, wall = crpx0_config.extract(s3.decode("utf-8"))
    by = {x["target"]: x["text"] for x in dec if x["target"]}
    urls = [u.strip() for u in by.get("REMOTE_URLS", "").split("|") if u.strip()]
    key = serialization.load_pem_public_key(lit["RSA_PUBLIC_KEY"].encode())
    spki = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    rows.append({
        "sha256": sha, **{f"stage1_{k}": v for k, v in pe_info(s1).items()},
        "stage2_sha256": H(s2), "stage2_ts": pe_info(s2)["ts"], "stage2_dll": pe_info(s2)["dll"],
        "stage1_ror": r1, "stage2_keys": [f"{k:#04x}" for k in k2], "bootstrap_len": blen, "stage3_sha256": H(s3), "stage3_len": len(s3),
        "operation_id": lit["OPERATION_ID"], "fernet_ts": ts, "affiliate_id": lit["AFFILIATE_ID"],
        "rsa_bits": key.key_size, "rsa_spki_sha256": H(spki),
        "xor_key_sha256": H(xk), "aes_key_b64_sha256": H(lit["AES_KEY_B64"]),
        "amsi_patch_key": lit["AMSI_PATCH_KEY"], "etw_patch_key": lit["ETW_PATCH_KEY"],
        "self_exclude_tag": lit["SELF_EXCLUDE_TAG"], "decoy_name": lit["DECOY_NAME"],
        "extension": lit["ENCRYPTED_EXT"], "remote_urls_defanged": [defang(u) for u in urls],
        "c2_auth_token": by.get("C2_AUTH_TOKEN"),
        "note_txt_sha256": H(by.get("RECOVERY_NOTE_TEMPLATE", "").encode()),
        "note_html_sha256": H(by.get("RECOVERY_NOTE_TEMPLATE_HTML", "").encode()),
        "wallpaper_sha256": H(wall) if wall else None,
        "dx_count": len(dec),
    })
    print(sha[:12], rows[-1]["operation_id"], rows[-1]["affiliate_id"], rows[-1]["stage3_sha256"][:12])
json.dump(rows, open(sys.argv[1], "w"), indent=1)
