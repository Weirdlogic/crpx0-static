#!/usr/bin/env bash
# Clean, end-to-end static reproduction of the CRPx0 unpack and configuration for
# 28685dff00aa1752b62a8580955b2530d63092bdcc0528b872a668cddad78c11.
#   A) Python pipeline: crpx0_stage1.py -> crpx0_stage2.py -> crpx0_config.py (ast + cryptography)
#   B) Go pipeline:     tools/go/crpx0repro (debug/pe, zlib, crypto/aes+hmac, regex), stdlib only
#   C) openssl CLI:     Fernet HMAC check + AES-128-CBC decrypt of ENCRYPTED_XOR_KEY
#   D) crpx0_decrypt_test.py: recovery tool on synthetic fixtures with our own keys
# then diffs A, B, C and the recorded evidence summary. Nothing from the sample
# is executed; nothing is resolved or contacted.
# Usage: tools/reproduce_crpx0.sh <empty_out_dir>
set -euo pipefail
R="$(cd "$(dirname "$0")/.." && pwd)"
SHA=28685dff00aa1752b62a8580955b2530d63092bdcc0528b872a668cddad78c11
S="$R/samples/$SHA"
E="$R/reports/crpx0/2026-10-15-28685dff00aa/evidence"
O="${1:?out dir}"; mkdir -p "$O"; [ -z "$(ls -A "$O")" ] || { echo "out dir must be empty"; exit 1; }
O="$(cd "$O" && pwd)"
[ "$(sha256sum "$S/sample.bin" | cut -d' ' -f1)" = "$SHA" ] || { echo "sample hash mismatch"; exit 1; }
export PATH="$HOME/.local/opt/go/bin:$PATH" GOFLAGS=-mod=mod GOTOOLCHAIN=local

echo "== A) Python pipeline"
mkdir -p "$O/py"
python3 -I "$R/tools/crpx0_stage1.py" "$S/sample.bin" "$O/py/stage2.bin" | head -1
python3 -I "$R/tools/crpx0_stage2.py" "$O/py/stage2.bin" "$O/py"
python3 -I "$R/tools/crpx0_config.py" "$O/py/stage3.py.txt" "$O/py/config.raw.json"

echo "== B) Go pipeline"
mkdir -p "$O/go"
( cd "$R/tools/go/crpx0repro" && go build -o "$O/crpx0repro" . )
"$O/crpx0repro" "$S/sample.bin" "$O/go"

echo "== C) openssl Fernet cross-check"
python3 -I - "$O/py/stage3.py.txt" "$O/ossl" <<'EOF'
# extract the two literals with a regex and write raw key/token parts for openssl
import base64, re, sys, os
src = open(sys.argv[1], encoding="utf-8").read()
k = base64.urlsafe_b64decode(re.search(r'^AES_KEY_B64 = b"([^"]+)"', src, re.M).group(1))
t = base64.urlsafe_b64decode(re.search(r'^ENCRYPTED_XOR_KEY = b"([^"]+)"', src, re.M).group(1))
os.makedirs(sys.argv[2])
w = lambda n, b: open(os.path.join(sys.argv[2], n), "wb").write(b)
w("signed.bin", t[:-32]); w("tag.hex", t[-32:].hex().encode()); w("ct.bin", t[25:-32])
w("sign_key.hex", k[:16].hex().encode()); w("enc_key.hex", k[16:].hex().encode()); w("iv.hex", t[9:25].hex().encode())
EOF
mac=$(openssl mac -digest SHA256 -macopt hexkey:"$(cat "$O/ossl/sign_key.hex")" -in "$O/ossl/signed.bin" HMAC | tr 'A-F' 'a-f')
[ "$mac" = "$(cat "$O/ossl/tag.hex")" ] && echo "openssl HMAC: OK" || { echo "openssl HMAC: MISMATCH"; exit 1; }
openssl enc -d -aes-128-cbc -K "$(cat "$O/ossl/enc_key.hex")" -iv "$(cat "$O/ossl/iv.hex")" -in "$O/ossl/ct.bin" -out "$O/ossl/xor_key.bin"
echo "openssl XOR key sha256: $(sha256sum "$O/ossl/xor_key.bin" | cut -d' ' -f1)"

echo "== D) recovery tool on synthetic fixtures (own keys)"
python3 -I "$R/tools/crpx0_decrypt_test.py" "$O/dectest" | grep -E '^(PASS|ALL|SOME)'
cp "$O/dectest/summary.json" "$O/decrypt_test_summary.json"

echo "== diff"
python3 -I - "$O" "$E/pipeline-summary.json" <<'EOF'
import hashlib, json, sys, os
O = sys.argv[1]
H = lambda b: hashlib.sha256(b).hexdigest()
py = json.load(open(f"{O}/py/config.raw.json"))
go = json.load(open(f"{O}/go/repro.json"))
s2 = open(f"{O}/py/stage2.bin", "rb").read(); s3 = open(f"{O}/py/stage3.py.txt", "rb").read()
A = {"stage2_sha256": H(s2), "stage3_sha256": H(s3),
     "xor_key_sha256": H(py["xor_key_fernet_decrypted"].encode("latin-1")),
     "fernet_timestamp": py["encrypted_xor_key_fernet_timestamp"],
     "dx": sorted((d["line"], d["len"], H(d["text"].encode("utf-8"))) for d in py["dx_strings"]),
     "remote_urls": [H(u.encode()) for u in py["remote_urls"]]}
B = {"stage2_sha256": go["stage2_sha256"], "stage3_sha256": go["stage3_sha256"],
     "xor_key_sha256": go["xor_key_sha256"], "fernet_timestamp": go["fernet_timestamp"],
     "dx": sorted((d["line"], d["len"], d["sha256"]) for d in go["dx_strings"]),
     "remote_urls": go["remote_url_sha256s"]}
C = H(open(f"{O}/ossl/xor_key.bin", "rb").read())
ok = True
for k in A:
    same = A[k] == B[k]; ok &= same
    print(f"{k:16} python==go: {same}" + ("" if k != "dx" else f"  ({len(A[k])} strings)"))
print(f"xor key         python==openssl: {A['xor_key_sha256'] == C}"); ok &= A["xor_key_sha256"] == C
if os.path.exists(sys.argv[2]):
    R = json.load(open(sys.argv[2]))
    rec = {k: (sorted(map(tuple, R[k])) if k == "dx" else R[k]) for k in A}
    same = rec == A; ok &= same
    print(f"matches recorded evidence/pipeline-summary.json: {same}")
else:
    json.dump(A, open(sys.argv[2], "w"), indent=1); print("recorded", sys.argv[2])
print("RESULT:", "IDENTICAL" if ok else "DIFFERENCES"); sys.exit(0 if ok else 1)
EOF
