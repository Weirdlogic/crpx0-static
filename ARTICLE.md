# Seven CRPx0 ransomware builds, unpacked statically: the key leaves in clear and much of the attack is broken

CRPx0 is a ransomware operation that appeared in mid-2026. In August the
Ransom-ISAC Research Team published a long analysis of several builds, and at
the end they listed seven files on MalwareBazaar they had not analysed,
calling them the best available independent test set for their detection
rules. I took those seven builds and unpacked them with static analysis only.
None of them ran on my machine.

- Reference sample: `28685dff00aa1752b62a8580955b2530d63092bdcc0528b872a668cddad78c11` (first seen 2026-08-04)
- Full technical report: [report.md](reports/crpx0/2026-10-15-28685dff00aa/report.md)

## Results

| | |
|---|---|
| Key handling | The victim's key is posted as JSON over plain HTTP to `hxxp://207.180.29[.]236:8080/relay[.]php` before any file is encrypted |
| Cryptography | Fernet (AES-128-CBC with HMAC) and RSA-4096; no weakness found |
| What survives | Everything after the first 1 MiB of each file; deleted originals; very likely the shadow copies |
| Broken in these builds | Lateral movement, the anti-debug check, the AMSI patch, and on 64-bit Windows the whole evasion layer |
| Builds | 7 builds for affiliate 21, made in 76 minutes on 2026-08-02 |
| Reproduced | Every layer rebuilt with Go and openssl: identical |

I did not resolve or contact any of the addresses in this write-up.

## The chain

```mermaid
flowchart LR
  A["Stage 1<br/>MinGW dropper"] -->|"xor, rotate, not, xor"| B["Stage 2<br/>Python-runtime installer"]
  B -->|"XOR-encoded script"| C["sys_service.py"]
  C -->|"base64 + zlib"| D["Stage 3<br/>Python ransomware"]
  D -->|"Fernet-wrapped key"| E["Configuration"]
```

1. Stage 1 is a small MinGW program with a 3.87 MB encrypted blob. Its
   decoder XORs each byte with one table, rotates it, inverts it and XORs it
   with a second table. It writes the result to `%LOCALAPPDATA%` under a name
   like `index.dll` and starts it.
2. Stage 2 downloads the official Python 3.10 embeddable runtime from
   python.org, installs `cryptography`, `requests` and `pywin32` with pip, and
   runs a script called `sys_service.py`. Before that it checks for a
   debugger, a small disk, little memory or a short uptime, and if it finds one
   it sleeps forever instead of exiting, which wastes a sandbox's time.
3. `sys_service.py` holds the ransomware as base64-encoded, zlib-compressed
   Python and runs it from memory.
4. The ransomware keeps its C2 addresses, token, ransom notes and commands as
   lists of numbers XORed with a key, and that key is itself encrypted with
   Fernet. I decoded all of it by reading the source with Python's parser,
   without running it.

![Stage 1 decoder](reports/crpx0/2026-10-15-28685dff00aa/figures/fig-stage1-decoder.svg)

## The key is sent in clear

The ransomware makes one random key per computer, encrypts the first MiB of
each file with it, and wraps the key with an RSA-4096 public key whose private
half only the operators have. That part is done properly. The RSA key passed
every weak-key test I ran, and there is no private key anywhere in the files.

The problem for the operators is what happens to the key before that. The
script sends it to its relay as a JSON field called `decryption_key`, over
plain HTTP, up to ten times before it encrypts a single file, and once more
at the end. Anyone with a packet capture, an IDS that logs HTTP bodies or a
proxy that records POST data has the key for that host. The key also sits in
the Python process's memory for the whole run, so a memory dump,
`pagefile.sys` or `hiberfil.sys` may hold it.

![Key handling](reports/crpx0/2026-10-15-28685dff00aa/figures/fig-key-handling.svg)

I wrote a recovery tool for this case. It searches captures, logs and memory
images for the key, checks each candidate against an encrypted file, and
decrypts. Without the key it writes out the part of each file that was never
encrypted. It is tested on synthetic files that I encrypted myself in the same
format with my own keys; it has not yet been used on a real victim's files.

Other things work in a victim's favour. Only the first 1 MiB of each file is
encrypted, so large files keep most of their content. Originals are deleted
with a plain `os.remove`, so they can often be undeleted from a hard disk or a
VM disk. Virtual disk files and SQL Server data files are not on the target
list at all.

## Much of the attack does not work

Reading the code closely turned up bugs that switch off large parts of it.

The lateral-movement function starts with `key.encode()`, but the key is
already a bytes object, which has no `encode` method. Python raises an
exception on that line, before any network discovery happens, so share
encryption and the push to other hosts never run.

The anti-debug check and the AMSI patch look up their Windows functions from
encoded names, but those three names do not decode with any key. They are the
same in all seven builds, while the builder re-encodes everything else per
build. Both features do nothing.

On 64-bit Windows the evasion layer fails as a whole. The script calls Windows
functions through Python's `ctypes` without declaring that they return
pointers, so `ctypes` keeps only the lower 32 bits of each address. Stage 2
installs 64-bit Python on every 64-bit Windows, where those addresses are
above 4 GB. The ntdll unhooking, the ETW patch and the injection into
explorer.exe all receive corrupted addresses and quietly give up.

![ctypes truncation](reports/crpx0/2026-10-15-28685dff00aa/figures/fig-ctypes.svg)

The UAC bypass writes a registry key that Windows does not read and starts
fodhelper in a way that is expected to fail. If that holds, the ransomware
runs without admin rights on a normal setup, and the commands that delete
shadow copies fail. I have not confirmed this part on a live system yet; it is
the one item in the report marked as expected rather than established.

## One builder, seven builds

The seven files were all built on 2026-08-02 within 76 minutes. Each build's
operation ID is a Unix timestamp, and it matches the time stamped inside the
build's encrypted key. Stage 2 was compiled about 18 seconds later and stage 1
about 36 seconds later, every time. The builder changes the rotate amount, the
XOR keys, the file name and several tags per build, and keeps the RSA key, the
C2 addresses, the ransom notes and the wallpaper the same.

![Builder timeline](reports/crpx0/2026-10-15-28685dff00aa/figures/fig-build-timeline.svg)

The wallpaper shown after encryption is a PNG with a C2PA content-credentials
manifest that names ChatGPT and GPT-4o as the tool that created it.

## Detections

Five YARA rules cover the dropper, the installer, the bootstrap script, the
Python payload and encrypted files. They match all seven builds at every stage
and none of 47,483 benign files on my machine. I also ran the rules
Ransom-ISAC published against the same files: they match the three DLL builds
and the Python payload but miss the four EXE builds and all seven bootstrap
scripts. The KQL and Elastic hunts are in `detections/` and have not been
tested against real telemetry yet.

## Checking the work

Every decoding step was rebuilt from the original file a second time in Go,
using only its standard library, and the configuration key was decrypted a
third time with the openssl command line. All three agree at every layer.
`tools/reproduce_crpx0.sh` runs the whole comparison.

## Prior work

The Ransom-ISAC Research Team's analysis covers the CRPx0 chain, the C2
relays, the token and the file format on other builds, and this work builds on
it. ProVendata, TheRavenFile and KELA have also reported on the group. The
report lists what each of them covers and where my results for these seven
builds differ.
