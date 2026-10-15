# crpx0-static

Static analysis of seven builds of the CRPx0 ransomware that were uploaded to
MalwareBazaar on 2026-08-04 (affiliate 21; reference sample SHA-256
`28685dff00aa1752b62a8580955b2530d63092bdcc0528b872a668cddad78c11`). Every
layer was decoded without running any of them, from the MinGW dropper down to
the Python ransomware and its configuration.

Read the write-up: [ARTICLE.md](ARTICLE.md)

Full technical report: [reports/crpx0/2026-10-15-28685dff00aa/report.md](reports/crpx0/2026-10-15-28685dff00aa/report.md)

## Results

- The victim's file key is sent as JSON over plain HTTP to the relay
  `hxxp://207.180.29[.]236:8080/relay[.]php` before encryption starts. A
  packet capture of that request is enough to decrypt the host.
- The encryption itself (Fernet with RSA-4096) has no weakness we could find.
  Only the first 1 MiB of each file is encrypted, originals are deleted
  without being wiped, and shadow copies very likely survive on default
  setups.
- Lateral movement, the anti-debug check, the AMSI patch and, on 64-bit
  Windows, the whole evasion layer fail because of bugs in the code.
- All seven builds decoded; what the builder changes per build is in
  [crosssample/builds.json](reports/crpx0/2026-10-15-28685dff00aa/crosssample/builds.json).
- Reproduced with a second toolchain (Go standard library and openssl):
  identical output at every layer.

## Repository layout

| Path | Contents |
|---|---|
| `tools/` | Decoders for each layer, the configuration extractor, the cross-build runner, the recovery tool and its tests, the YARA validator, the figure renderer and the reproduction script. None of them runs sample code. |
| `tools/go/crpx0repro/` | Independent re-implementation in Go, standard library only |
| `detections/` | YARA rules, KQL (Microsoft Defender XDR) and Elastic (EQL, ES\|QL) hunts |
| `reports/crpx0/2026-10-15-28685dff00aa/` | Report (Markdown and HTML), figures, evidence, cross-build results |

## Recovering files

`tools/crpx0_decrypt.py` is a clean-room recovery tool for `.crpx0` files.
It needs the victim's key, which it can find in a packet capture, a proxy or
IDS log, a memory image, `pagefile.sys` or `hiberfil.sys`; every candidate is
checked against an encrypted file before use. Without the key it can still
write out the part of each file that was never encrypted. It never modifies
or deletes its input. It has been tested on synthetic files only
(`tools/crpx0_decrypt_test.py`).

```bash
python3 tools/crpx0_decrypt.py keyhunt --check some_file.docx.crpx0 capture.pcap
python3 tools/crpx0_decrypt.py decrypt --key <key> --out recovered/ *.crpx0
python3 tools/crpx0_decrypt.py salvage --out partial/ *.crpx0
```

## Reproduce the analysis

Download the reference sample from MalwareBazaar into
`samples/28685dff00aa1752b62a8580955b2530d63092bdcc0528b872a668cddad78c11/`
with `tools/fetch-sample.py` and extract it with `tools/unzip-sample.py`
(the scripts keep it zipped until analysis and never execute it). Requires
Python 3 with `cryptography`, Go 1.22 or later, openssl and objdump.

```bash
tools/reproduce_crpx0.sh /path/to/empty_dir
```

## What is not here

No samples, no decoded stages, no stage-3 source, no decompiled code and no
disassembly. The figures quote short excerpts with line numbers. Publish
hashes, not samples.

## Prior work

The Ransom-ISAC Research Team published the most complete analysis of CRPx0
(other builds, 2026-08-27); ProVendata, TheRavenFile and KELA have also
reported on it. The report's *Prior art* section lists what each source
covers and what this analysis adds.
