#!/usr/bin/env python3
"""Render the CRPx0 report figures as theme-aware SVG (CSS variables of the
report template, so they work in light and dark mode).

Every code panel is read from a real artefact at render time, never retyped:
  fig-stage1-decoder.svg   Ghidra 12.1.4 headless decompile (evidence/stage1-decomp.c)
                           next to objdump of the same loop in the sample
  fig-build-variation.svg  per-build values from crosssample/builds.json and the
                           objdump of each build's decoder
  fig-key-handling.svg     stage 3 source lines (quarantined copy), key flow + bug
  fig-ctypes.svg           stage 3 resolve_api lines + evidence/ctypes_truncation.txt
  fig-stage1-entropy.svg   Shannon entropy per 4 KiB block of the stage 1 file
  fig-build-timeline.svg   OPERATION_ID / stage 2 / stage 1 timestamps per build

Usage: crpx0_figures.py <report_dir> <samples_dir>
"""
import collections
import datetime as dt
import html
import json
import math
import os
import re
import subprocess
import sys

FONT = 'font-family="var(--mono)"'
W = 960


def esc(s):
    return html.escape(s, quote=False)


def svg(h, body):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {h}" width="{W}" height="{h}">'
            f'<rect width="{W}" height="{h}" style="fill:var(--surface)"/>{body}</svg>\n')


def text(x, y, s, size=12, cls="fg", weight="normal", anchor="start"):
    color = {"fg": "var(--fg)", "muted": "var(--muted)", "alert": "var(--alert)", "link": "var(--link)"}[cls]
    return (f'<text xml:space="preserve" x="{x}" y="{y}" {FONT} font-size="{size}" font-weight="{weight}" '
            f'text-anchor="{anchor}" style="fill:{color}">{esc(s)}</text>')


def foot(y, s, width=W - 20, size=11):
    """Muted footnote wrapped to the figure width; returns (svg, lines)."""
    maxc = int(width / (size * 0.6))
    words, lines, cur = s.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > maxc:
            lines.append(cur); cur = w
        else:
            cur = (cur + " " + w).strip()
    lines.append(cur)
    return "".join(text(10, y + i * 15, l, size, "muted") for i, l in enumerate(lines)), len(lines)


def panel(x, y, w, title, lines, hl=(), note=None, size=11.5, lh=16, maxc=None):
    """Code panel; hl = indices of highlighted lines."""
    maxc = maxc or int((w - 20) / (size * 0.6))
    h = 34 + lh * len(lines) + (18 if note else 0)
    out = [f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="4" style="fill:var(--tint);stroke:var(--rule)"/>',
           text(x + 10, y + 20, title, 12, "muted", "bold")]
    for i, l in enumerate(lines):
        ly = y + 38 + i * lh
        if i in hl:
            out.append(f'<rect x="{x + 4}" y="{ly - 12}" width="{w - 8}" height="{lh}" '
                       f'style="fill:var(--alert);fill-opacity:0.14"/>')
        s = l.rstrip("\n").replace("\t", "    ")
        out.append(text(x + 10, ly, s if len(s) <= maxc else s[:maxc - 1] + "…", size,
                        "alert" if i in hl else "fg"))
    if note:
        out.append(text(x + 10, y + h - 8, note, 11, "muted"))
    return "".join(out), h


def objdump(path, start, stop):
    o = subprocess.run(["objdump", "-d", "-M", "intel", f"--start-address={start:#x}",
                        f"--stop-address={stop:#x}", path], capture_output=True, text=True).stdout
    rows = []
    for l in o.splitlines():
        m = re.match(r"\s*([0-9a-f]+):\s+(?:[0-9a-f]{2} )+\s*\t(.*)", l)
        if m:
            rows.append((int(m.group(1), 16), re.sub(r"\s+", " ", m.group(2)).strip()))
    return rows


def fig_stage1(rep, sample):
    dec = open(os.path.join(rep, "evidence/stage1-decomp.c")).read()
    body = dec[dec.index("// ==== FUN_00401566"):]
    body = body[:body.index("\n}\n") + 3].splitlines()
    keep = [l for l in body if l.strip() and not l.startswith("//") and "WARNING" not in l][:24]
    hl_c = {i for i, l in enumerate(keep) if re.search(r">> 1|~\(|\^ \(&DAT_007b38[48]0\)\[local_14", l)}
    asm = objdump(sample, 0x4015c7, 0x401658)
    pick = [f"{a:08x}  {t}" for a, t in asm if re.search(r"0x7b38[48]0\]|shl|shr|not|0x403020|and eax,0x3f", t)][:22]
    hl_a = {i for i, l in enumerate(pick) if re.search(r"shl|shr|not|0x7b38[48]0\]", l)}
    p1, h1 = panel(10, 34, 520, "Ghidra 12.1.4 decompiler: FUN_00401566 (stage 1 decoder)", keep, hl_c, maxc=80, size=10.5, lh=15)
    p2, h2 = panel(540, 34, 410, "objdump: per-byte loop at 0x4015c7 (same function)", pick, hl_a, maxc=62, size=10.5, lh=15)
    fs, n = foot(0, "Highlighted: the four operations of the transform. Sample 28685dff...; addresses as loaded at "
                 "0x400000. Reimplemented in tools/crpx0_stage1.py and tools/go/crpx0repro.")
    h = max(h1, h2) + 50 + 15 * n
    title = text(10, 22, "Stage 1: k1/k2 tables unmasked by one byte each, then per byte: xor k2 -> ror 1 -> not -> xor k1", 13, "fg", "bold")
    return svg(h, title + p1 + p2 + foot(max(h1, h2) + 56, "Highlighted: the four operations of the transform. "
               "Sample 28685dff...; addresses as loaded at 0x400000. Reimplemented in tools/crpx0_stage1.py and "
               "tools/go/crpx0repro.")[0])


def fig_variation(rep, samples):
    rows = json.load(open(os.path.join(rep, "crosssample/builds.json")))
    rows.sort(key=lambda r: r["fernet_ts"])
    head = ["build", "type", "built (UTC)", "stage-1 op", "ror", "stage-2 keys cfg/boot", "drop name", "exclude tag"]
    xs = [16, 116, 166, 270, 420, 470, 640, 780]
    out = [text(10, 22, "Seven builds, one builder: what changes per build (affiliate 21, same RSA key, C2 and notes)", 13, "fg", "bold")]
    for x, hd in zip(xs, head):
        out.append(text(x, 52, hd, 11.5, "muted", "bold"))
    out.append(f'<line x1="10" y1="60" x2="{W - 10}" y2="60" style="stroke:var(--rule)"/>')
    for i, r in enumerate(rows):
        y = 82 + i * 26
        s1 = os.path.join(samples, r["sha256"], "sample.bin")
        b = open(s1, "rb").read()
        j = b.find(b"LOCALAPPDATA")
        drop = re.search(rb"\\([a-z]{3,8}\.dll)", b[j:j + 64]).group(1).decode()
        op = f"shr al,{r['stage1_ror']}" if r["stage1_ror"] > 1 else "shr al,1"
        vals = [r["sha256"][:8] + "…", "DLL" if r["stage1_dll"] else "EXE",
                dt.datetime.fromtimestamp(r["fernet_ts"], dt.timezone.utc).strftime("%H:%M:%S"),
                op, str(r["stage1_ror"]), " / ".join(r["stage2_keys"]), drop, r["self_exclude_tag"]]
        if i % 2:
            out.append(f'<rect x="10" y="{y - 17}" width="{W - 20}" height="26" style="fill:var(--tint)"/>')
        for x, v in zip(xs, vals):
            out.append(text(x, y, v, 12, "alert" if x in (270, 420, 470) else "fg"))
    fs, n = foot(82 + len(rows) * 26 + 8, "Source: crosssample/builds.json (tools/crpx0_crosssample.py); drop name read "
                 "from each stage 1; ror = rotate amount found by tools/crpx0_stage1.py locate(). Highlighted columns change "
                 "in every build; ror 7 = rol 1.")
    out.append(fs); h = 82 + len(rows) * 26 + 16 + 15 * n
    return svg(h, "".join(out))


def src_lines(stage3, ranges):
    L = open(stage3, encoding="utf-8").read().split("\n")
    out = []
    for a, b in ranges:
        if out:
            out.append("   ⋮")
        out += [f"{n:5d}  {L[n - 1]}" for n in range(a, b + 1)]
    return out


def fig_keys(rep, stage3):
    lines = src_lines(stage3, [(1298, 1300), (1302, 1305), (1310, 1312), (1339, 1341), (1350, 1350), (1370, 1372)])
    hl = {i for i, l in enumerate(lines) if re.search(r"generate_key|decryption_key|read\(1024|os.remove|domain_encrypt", l)}
    p1, h1 = panel(10, 34, 940, "stage 3 (sys_service.py) stage2_encrypt(): where the key goes", lines, hl, maxc=150, size=10.5, lh=15)
    bug = src_lines(stage3, [(1040, 1040), (1051, 1054)])
    p2, h2 = panel(10, 44 + h1, 940, "stage 3 domain_encrypt_network(fernet, key): key is bytes, so key.encode() raises AttributeError",
                   bug, {i for i, l in enumerate(bug) if "key.encode" in l}, maxc=150, size=10.5, lh=15)
    fs, n = foot(44 + h1 + h2 + 18, "Line numbers: stage3_752b8fe4... (sample 28685dff...). The same code is in all seven builds.")
    h = 44 + h1 + h2 + 24 + 15 * n
    title = text(10, 22, "One random key per host, sent in clear JSON over plain HTTP before and after encryption", 13, "fg", "bold")
    return svg(h, title + p1 + p2 + fs)


def fig_ctypes(rep, stage3):
    a = src_lines(stage3, [(69, 80)])
    hla = {i for i, l in enumerate(a) if re.search(r"GetModuleHandleW|GetProcAddress|LoadLibraryW", l)}
    p1, h1 = panel(10, 34, 940, "stage 3 resolve_api(): no restype on GetModuleHandleW / GetProcAddress",
                   a, hla, maxc=150, size=10.5, lh=15)
    harness = open(os.path.join(rep, "evidence/ctypes_truncation.txt")).read().strip().splitlines()
    p2, h2 = panel(10, 44 + h1, 940, "harness (no sample code): the same default restype on a 64-bit Python",
                   harness, {1, 3}, maxc=150, size=10.5, lh=15)
    fs, n = foot(44 + h1 + h2 + 18, "Stage 2 installs the amd64 Python embed whenever IsWow64Process is true, i.e. on every 64-bit Windows.")
    h = 44 + h1 + h2 + 24 + 15 * n
    title = text(10, 22, "On 64-bit Python a returned pointer keeps only its low 32 bits: handles and API addresses are corrupted", 13, "fg", "bold")
    return svg(h, title + p1 + p2 + fs)


def fig_entropy(rep, sample):
    b = open(sample, "rb").read()
    blk = 4096
    ent = []
    for i in range(0, len(b), blk):
        c = collections.Counter(b[i:i + blk]); n = sum(c.values())
        ent.append(-sum(v / n * math.log2(v / n) for v in c.values()))
    x0, x1, y0, y1 = 60, W - 20, 50, 250
    sx = (x1 - x0) / len(b)
    pts = " ".join(f"{x0 + i * blk * sx:.1f},{y1 - e / 8 * (y1 - y0):.1f}" for i, e in enumerate(ent))
    out = [text(10, 22, "Stage 1 file: 7 KB of code, then a 3.87 MB encrypted blob in .data (entropy per 4 KiB block)", 13, "fg", "bold"),
           f'<rect x="{x0 + 0x2000 * sx:.1f}" y="{y0}" width="{(0x3b2a00 - 0x2000) * sx:.1f}" height="{y1 - y0}" '
           f'style="fill:var(--alert);fill-opacity:0.08"/>',
           text(x0 + 0x2000 * sx + 6, y0 + 16, ".data: encrypted stage 2 (decoded by FUN_00401566)", 11, "alert")]
    for v in (0, 2, 4, 6, 8):
        y = y1 - v / 8 * (y1 - y0)
        out.append(f'<line x1="{x0}" y1="{y:.1f}" x2="{x1}" y2="{y:.1f}" style="stroke:var(--rule)"/>')
        out.append(text(x0 - 8, y + 4, str(v), 11, "muted", anchor="end"))
    out.append(f'<polyline points="{pts}" fill="none" style="stroke:var(--fg)" stroke-width="1.2"/>')
    for off, lab in ((0, "0"), (1 << 20, "1 MB"), (2 << 20, "2 MB"), (3 << 20, "3 MB")):
        out.append(text(x0 + off * sx, y1 + 18, lab, 11, "muted", anchor="middle"))
    fs, n = foot(290, "Mean entropy of .data 7.97; code and headers below 6. Sample 28685dff...; the decoded stage 2 "
                 "(same size) drops to 6.0 because its .data is base64 text of the payload.")
    out.append(fs)
    return svg(296 + 15 * n, "".join(out))


def fig_timeline(rep):
    rows = sorted(json.load(open(os.path.join(rep, "crosssample/builds.json"))), key=lambda r: r["fernet_ts"])
    x0, x1, span = 330, W - 40, 45
    X = lambda d: x0 + d / span * (x1 - x0)
    out = [text(10, 22, "2026-08-02: seven builds in 76 minutes, each produced by the same three-step pipeline", 13, "fg", "bold"),
           text(10, 50, "build", 11.5, "muted", "bold"), text(130, 50, "OPERATION_ID (UTC)", 11.5, "muted", "bold"),
           text(x0, 50, "seconds after OPERATION_ID", 11.5, "muted", "bold")]
    cols = {"P": "var(--alert)", "2": "var(--link)", "1": "var(--fg)"}
    for i, r in enumerate(rows):
        y = 78 + i * 28
        if i % 2:
            out.append(f'<rect x="10" y="{y - 16}" width="{W - 20}" height="28" style="fill:var(--tint)"/>')
        out.append(text(10, y + 4, f'{r["sha256"][:8]}… {"DLL" if r["stage1_dll"] else "EXE"}', 11.5))
        out.append(text(130, y + 4, dt.datetime.fromtimestamp(r["fernet_ts"], dt.timezone.utc).strftime("%H:%M:%S")
                        + f'  (OP_{r["fernet_ts"]})', 11.5))
        out.append(f'<line x1="{x0}" y1="{y}" x2="{x1}" y2="{y}" style="stroke:var(--rule)"/>')
        d2, d1 = r["stage2_ts"] - r["fernet_ts"], r["stage1_ts"] - r["fernet_ts"]
        out.append(f'<line x1="{X(0):.1f}" y1="{y}" x2="{X(d1):.1f}" y2="{y}" style="stroke:var(--muted)" stroke-width="2"/>')
        for d, k in ((0, "P"), (d2, "2"), (d1, "1")):
            out.append(f'<circle cx="{X(d):.1f}" cy="{y}" r="5" style="fill:{cols[k]}"/>')
        out.append(text(X(d2), y - 8, f"+{d2}s", 10, "link", anchor="middle"))
        out.append(text(X(d1), y - 8, f"+{d1}s", 10, "fg", anchor="middle"))
    yb = 78 + len(rows) * 28
    for d in range(0, span + 1, 5):
        out.append(text(X(d), yb, str(d), 10.5, "muted", anchor="middle"))
    fs, n = foot(yb + 24, "Red = payload stamped (Fernet timestamp of ENCRYPTED_XOR_KEY, equal to the OPERATION_ID); "
                 "blue = stage 2 PE TimeDateStamp; black = stage 1 PE TimeDateStamp. Source: crosssample/builds.json.")
    out.append(fs)
    return svg(yb + 30 + 15 * n, "".join(out))


if __name__ == "__main__":
    rep, samples = sys.argv[1], sys.argv[2]
    ref = os.path.join(samples, "28685dff00aa1752b62a8580955b2530d63092bdcc0528b872a668cddad78c11")
    stage3 = [os.path.join(ref, f) for f in os.listdir(ref) if f.startswith("stage3_")][0]
    figs = os.path.join(rep, "figures")
    os.makedirs(figs, exist_ok=True)
    out = {
        "fig-stage1-decoder.svg": fig_stage1(rep, os.path.join(ref, "sample.bin")),
        "fig-build-variation.svg": fig_variation(rep, samples),
        "fig-key-handling.svg": fig_keys(rep, stage3),
        "fig-ctypes.svg": fig_ctypes(rep, stage3),
        "fig-stage1-entropy.svg": fig_entropy(rep, os.path.join(ref, "sample.bin")),
        "fig-build-timeline.svg": fig_timeline(rep),
    }
    for n, s in out.items():
        open(os.path.join(figs, n), "w").write(s)
        print(n, len(s))
