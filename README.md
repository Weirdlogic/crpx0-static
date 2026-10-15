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
- No exploitable weakness was found in the encryption itself (Fernet with
  RSA-4096). Only the first 1 MiB of each file is encrypted, originals are
  deleted without being wiped, and shadow copies may survive on default
  setups (check on each host).
- Lateral movement, the anti-debug check and the AMSI patch fail because of
  bugs in the code, and on 64-bit Windows 8.1 and later the evasion layer
  receives truncated addresses in default configurations.
- All seven builds decoded; what the builder changes per build is in
  [crosssample/builds.json](reports/crpx0/2026-10-15-28685dff00aa/crosssample/builds.json).
- Reproduced with a second toolchain (Go standard library and openssl):
  identical output at every layer.

## Repository layout

| Path | Contents |
|---|---|
| `tools/` | Decoders for each layer, the configuration extractor, the cross-build runner, the recovery tool and its tests, the YARA validator, the figure renderer and the reproduction script. None of them runs sample code. |
| `tools/go/crpx0repro/` | Independent re-implementation in Go, standard library only |
| `tools/go/crpx0fixtures/` | Independent Go writer of `.crpx0` test files, for checking the recovery tool |
| `detections/` | YARA rules, KQL (Microsoft Defender XDR) and Elastic (EQL, ES\|QL) hunts |
| `reports/crpx0/2026-10-15-28685dff00aa/` | Report (Markdown and HTML), figures, evidence, cross-build results |

## Recovering files

`tools/crpx0_decrypt.py` is a clean-room recovery tool for `.crpx0` files.
It needs the victim's key, which it can find in a packet capture, a proxy or
IDS log, a memory image, `pagefile.sys` or `hiberfil.sys`; every candidate is
checked against an encrypted file before use. Without the key it can still
write out the part of each file that was never encrypted. It never modifies
or deletes its input. It has been tested on synthetic files only: 15 checks
on files from the Python test writer (`tools/crpx0_decrypt_test.py`) and 11
files written independently by a Go implementation of the format
(`tools/go/crpx0fixtures`, `tools/crpx0_decrypt_crosscheck.py`), all restored
byte for byte. It has not been used on a real victim's files.

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
