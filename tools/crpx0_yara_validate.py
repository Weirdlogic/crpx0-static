#!/usr/bin/env python3
"""Validate the CRPx0 YARA rules: hits per positive class and false positives
on a local benign corpus. Scans with yr (YARA-X); scanning reads files only.

Positives (all statically decoded from the 7 MalwareBazaar builds, plus
synthetic encrypted fixtures made with our own keys):
  stage1     samples/<sha>/sample.bin           (7)
  stage2     samples/<sha>/stage2_*.bin          (7)
  stage3     samples/<sha>/stage3_*.bin          (7)
  bootstrap  samples/<sha>/bootstrap_*.bin       (7)
  encrypted  <fixtures dir>/enc/*.crpx0          (10)
Benign: every regular file under the given directories.

Usage: crpx0_yara_validate.py <shas.txt> <fixtures_dir> <out.json> <benign_dir>...
"""
import collections
import glob
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = sorted(glob.glob(os.path.join(ROOT, "detections/yara/crpx0_*.yar")))
EXPECT = {"stage1": "CRPX0_Stage1_Dropper_Stub", "stage2": "CRPX0_Stage2_Python_Installer",
          "stage3": "CRPX0_Python_Payload", "bootstrap": "CRPX0_Bootstrap_Script",
          "encrypted": "CRPX0_Encrypted_File"}


def scan(target):
    """Return {path: set(rule names)} for one file or directory, all rules."""
    hits = collections.defaultdict(set)
    for r in RULES:
        p = subprocess.run(["yr", "scan", "-w", "-o", "ndjson", "-r", r, target] if os.path.isdir(target)
                           else ["yr", "scan", "-w", "-o", "ndjson", r, target],
                           capture_output=True, text=True)
        for line in p.stdout.splitlines():
            try:
                o = json.loads(line)
            except ValueError:
                continue
            for m in o.get("rules", []):
                hits[o["path"]].add(m["identifier"])
    return hits


def main(shas, fixtures, out, benign):
    shas = open(shas).read().split()
    classes = {
        "stage1": [f"{ROOT}/samples/{h}/sample.bin" for h in shas],
        "stage2": sum((glob.glob(f"{ROOT}/samples/{h}/stage2_*.bin") for h in shas), []),
        "stage3": sum((glob.glob(f"{ROOT}/samples/{h}/stage3_*.bin") for h in shas), []),
        "bootstrap": sum((glob.glob(f"{ROOT}/samples/{h}/bootstrap_*.bin") for h in shas), []),
        "encrypted": sorted(glob.glob(f"{fixtures}/enc/*.crpx0")),
    }
    res = {"rules": [os.path.relpath(r, ROOT) for r in RULES], "positives": {}, "benign": {}}
    for cls, files in classes.items():
        per = {}
        for f in files:
            per[f] = sorted(scan(f).get(f, set()))
        exp = EXPECT[cls]
        res["positives"][cls] = {
            "files": len(files), "expected_rule": exp,
            "hit": sum(exp in v for v in per.values()),
            "other_rules": sorted({r for v in per.values() for r in v if r != exp}),
        }
        print(f"{cls:10} {res['positives'][cls]['hit']}/{len(files)} {exp}  other: {res['positives'][cls]['other_rules']}")
    total, fp = 0, collections.Counter()
    fp_files = []
    for d in benign:
        n = sum(len(fs) for _, _, fs in os.walk(d))
        total += n
        for path, rules in scan(d).items():
            fp.update(rules)
            fp_files.append({"path": path, "rules": sorted(rules)})
        print(f"benign {d}: {n} files")
    res["benign"] = {"dirs": benign, "files": total, "hits_by_rule": dict(fp), "hit_files": fp_files}
    print(f"benign files {total}, false positives: {dict(fp) or 0}")
    json.dump(res, open(out, "w"), indent=1)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:])
