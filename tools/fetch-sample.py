#!/usr/bin/env python3
"""Download ONE sample from MalwareBazaar into quarantine.

    python3 tools/fetch-sample.py <sha256> [--info-only]

Writes samples/<sha256>/info.json and samples/<sha256>/<sha256>.zip
(MalwareBazaar's AES-encrypted zip, password "infected"). The zip is never
unpacked or executed here; analysis tools unpack it only inside samples/<sha256>/.
The API key is read from Abuse.ch/.env (API_KEY=...) and never printed.
"""
import argparse
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV = ROOT / "Abuse.ch" / ".env"
API = "https://mb-api.abuse.ch/api/v1/"
UA = "research-lab/1.0"


def api_key():
    for line in ENV.read_text().splitlines():
        if line.startswith("API_KEY="):
            return line.split("=", 1)[1].strip().strip("\"'")
    sys.exit(f"API_KEY not found in {ENV}")


def post(fields, key):
    req = urllib.request.Request(API, data=urllib.parse.urlencode(fields).encode(),
                                 headers={"Auth-Key": key, "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.headers.get_content_type(), r.read()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sha256")
    ap.add_argument("--info-only", action="store_true", help="metadata only, no download")
    args = ap.parse_args()
    sha = args.sha256.lower()
    if not re.fullmatch(r"[0-9a-f]{64}", sha):
        sys.exit("expected a 64-character SHA-256")

    key = api_key()
    ctype, body = post({"query": "get_info", "hash": sha}, key)
    info = json.loads(body)
    if info.get("query_status") != "ok":
        sys.exit(f"MalwareBazaar get_info: {info.get('query_status')}")
    meta = info["data"][0]

    dest = ROOT / "samples" / sha
    dest.mkdir(parents=True, exist_ok=True)
    os.chmod(ROOT / "samples", 0o700)
    os.chmod(dest, 0o700)
    (dest / "info.json").write_text(json.dumps(meta, indent=1))
    print(f"{sha}\n  family: {meta.get('signature')}  type: {meta.get('file_type')}  "
          f"size: {meta.get('file_size')}  first seen: {meta.get('first_seen')}\n"
          f"  tags: {', '.join(meta.get('tags') or [])}")

    if args.info_only:
        return
    out = dest / f"{sha}.zip"
    if out.exists():
        print(f"  already quarantined: {out.relative_to(ROOT)}")
        return
    ctype, body = post({"query": "get_file", "sha256_hash": sha}, key)
    if ctype == "application/json" or not body.startswith(b"PK"):
        sys.exit(f"MalwareBazaar get_file failed: {body[:200]!r}")
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(body)
    print(f"  quarantined (zipped, password 'infected'): {out.relative_to(ROOT)}  {len(body)} bytes")


if __name__ == "__main__":
    main()
