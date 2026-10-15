# CRPx0 (builds of 2026-08-02) — crypto review and implementation faults

Line numbers refer to stage 3 of 28685dff… (`stage3_752b8fe4e67803e1`, 1,768
lines); all seven builds share the code (cross-build diff: only builder
constants and re-keyed `dx` lists differ). Nothing was executed. "Inferred"
items follow from the code plus documented Python/Windows behaviour and need
confirmation in an isolated Windows VM (test given for each).

## A. Cryptography — no exploitable flaw found

| Check | Result | Evidence |
|---|---|---|
| File key generation | `Fernet.generate_key()` = `os.urandom(32)`; one key per run (per host) | L1298 |
| Per-file IV | Fernet draws a fresh 16-byte IV per `encrypt()` | L1341 (library) |
| Key protection | RSA-4096, e = 65537, OAEP-SHA256, public key only | L44–58, L1310–1314 |
| Embedded private key | none in any stage of any build (`PRIVATE KEY` / `BEGIN RSA`: 0 hits in 28 files) | grep, this note |
| Weak RSA modulus | no factor < 2·10⁶; Fermat 2·10⁶ iterations: no; Pollard p−1 B1 = 10⁶: no; ROCA fingerprint: no | `rsa-key-checks.json` |
| Environmental keying | `get_env_key()` defined (L334) but **never called** | grep |
| Key reuse across victims | no (urandom per run); the RSA key is shared by all 7 builds (affiliate 21) | `crosssample/builds.json` |

Conclusion: without the operator's RSA private key, the first MiB of a file
cannot be decrypted from the file alone. Recovery has to come from where the
key or the plaintext leaks (B, C).

## B. Key exposure (observed)

1. **Key sent in clear over HTTP, twice.** `key_handshake` with
   `{'decryption_key': key, 'pre_encrypt': '1'}` up to 10 times *before* any
   file is touched (L1300–1309), and again with status `encrypted` (L1370).
   First relay is `hxxp://207.180.29[.]236:8080/relay[.]php` (plain HTTP).
   Full packet capture, an IDS with HTTP body logging, or a TLS-free proxy
   log of that POST yields the key → `crpx0_decrypt.py keyhunt`.
2. **The onion relay is very likely unreachable** (inferred): `urllib` with
   no proxy configuration cannot resolve `.onion`, so the HTTP relay is the
   path that works in practice. *VM test:* run with the HTTP relay blackholed
   and watch for any outbound connection.
3. **Key in process memory** for the whole run: `key` (bytes), two
   `key.decode()` strings in dicts, the JSON request body per attempt
   (L522–546). A memory capture of `python(w).exe`, `pagefile.sys`,
   `hiberfil.sys` or a crash dump may contain the 44-char base64 key →
   `keyhunt --any` (validated on a synthetic 53 MiB image).
4. **The key is not written to disk** by the malware: not in `crpx0_debug.log`
   (PyLog lines L1306/1309 omit it), not in `scan_report.json`. The C2's
   *response* body is logged (L553); if the panel echoes the key, the debug log
   would hold it (unknown).

## C. Plaintext that survives (observed in code)

1. **Partial encryption**: only `read(1024*1024)` is encrypted; the rest of
   the file is copied in clear (L1339–1347). Files > 1 MiB keep everything
   after the first MiB (`crpx0_decrypt.py salvage`).
2. **Originals are deleted, not wiped**: the `.crpx0` copy is written as a new
   file, then `os.remove(file_path)` (L1350). On HDDs and on VM disks without
   UNMAP/TRIM the original clusters remain until reused → undelete/carving.
   NTFS-resident small files (≲ 700 bytes) keep their data in the freed MFT
   record.
3. **Self-destruct does not wipe either**: the VBS opens each file with
   `OpenTextFile(path, 2)` and writes one space (L1014–1024) — that truncates,
   it does not overwrite clusters; then `DeleteFolder` removes subfolders
   without even that. `crpx0_debug.log`, `scan_report.json` (the full target
   list), and the deleted exfil ZIP `data_<6hex>_<OPID>.zip` (L815–870; up to 15
   original files, plaintext) are carvable from `%TEMP%\<decoy folder>`.
4. **Coverage gaps**: no `.vmdk/.vhd/.vhdx/.qcow2/.vdi`, no SQL Server
   `.mdf/.ldf/.ndf`, no `.iso` in FILE_EXTENSIONS (L428–470); no database or
   Office processes in the kill list (L896–918), so files locked by a running
   SQL Server, Outlook (`.pst/.ost` are targeted) or Office fail to open and
   are skipped silently (`except` + log, L1358–1360).
5. **Whole-file reads**: `rest = f.read()` loads the entire file; 32 worker
   threads (L1361) reading multi-GB files can raise `MemoryError` → file
   skipped (inferred; likely on 32-bit Python).

## D. Faults that disable parts of the attack

| # | Fault | Lines | Consequence | Confidence | VM test |
|---|---|---|---|---|---|
| D1 | `domain_encrypt_network` calls `key.encode()` on `bytes` | L1053 | `AttributeError` before any discovery: no SMB share encryption, no WMI/schtasks push, no SYSVOL GPO script; only `propagation_started` / `propagation_error` reach the C2 | high (Python semantics) | run in a domain lab; expect `propagation_error` with "'bytes' object has no attribute 'encode'" |
| D2 | IsDebuggerPresent / `amsi.dll` / `AmsiScanBuffer` lists decode under no key; identical in all builds while every other list is re-keyed | L99, L291–292 | `check_debugger` and `patch_amsi` resolve nothing and return | high (observed) | — |
| D3 | **ctypes calls without `restype`**: `GetModuleHandleW`, `LoadLibraryW`, `GetProcAddress`, `VirtualAllocEx` return 32-bit `int` | L74–77, L259, L1604, L1643 | On 64-bit Python (installed on every 64-bit Windows: stage 2 picks the amd64 embed when `IsWow64Process` is true) module handles and addresses are truncated → `resolve_api` returns `None`; `unhook_ntdll`, `patch_etw`, `stealth_sleep` (falls back to `time.sleep`) and `inject_into_explorer` fail inside their `try/except`. Commands then run via `subprocess` from `python(w).exe`, not `explorer.exe` | high for the truncation (`ctypes_truncation.txt`), medium for each downstream effect | run on Win10/11 x64; expect `crpx0_debug.log` without "patch applied" lines and `cmd.exe` children of `python.exe` |
| D4 | `inject_into_explorer` returns 0 even if `CreateRemoteThread` fails | L1651–1657 | on 32-bit Windows (where D3 does not bite) a failed thread still counts as success; the command never runs, no fallback | high (observed) | — |
| D5 | UAC "bypass" writes `ms-settings\shell\open<6 hex>\command` and starts fodhelper with `subprocess.run` (CreateProcess) | L972–999 | fodhelper's default verb is `open`, so the suffixed key is never read; and CreateProcess on an auto-elevating binary is expected to fail with ERROR_ELEVATION_REQUIRED (740) → exception → `return False` → payload continues **unelevated**, leaving the registry key behind (a durable IOC). If instead fodhelper starts, `uac_bypass` returns True and `main` **exits without encrypting** (L1707–1708) | medium (Windows behaviour, not run) | run as a standard and as a split-token admin user |
| D6 | All recovery-inhibition and AV-kill commands need admin | L601–614, L941–958 | With D5, a default-configured host (UAC on, user not elevated) keeps its **volume shadow copies and backup catalog**; `taskkill`/`sc stop`/`net stop` on AV fail; the ONLOGON task (L579–596) needs admin and fails | medium | check `vssadmin list shadows` after a run as a standard user |
| D7 | `run_capture` reads the temp output 0.5 s after `WinExec` returns (WinExec does not wait for the command) | L1660–1679 | where injection works (32-bit), `tasklist`/`sc query` VM checks read empty output | medium | — |
| D8 | No expiry / kill-switch in these builds | stub `0x4014f0`, stage 2, stage 3 | `GetSystemTime`/`GetTickCount` feed opaque junk arithmetic only; Ransom-ISAC reports expiry checks in other builds | high (observed) | — |

## E. What this means for a victim of these builds (ranked)

1. Look for the key on the wire (PCAP / IDS / proxy bodies for POSTs to
   `207.180.29[.]236:8080`) — one hit decrypts every file on that host.
2. Check volume shadow copies (`vssadmin list shadows`) — likely intact if the
   user was not running elevated (D5/D6).
3. If the host was not rebooted or has a pagefile/hiberfil: capture memory and
   run `keyhunt --any` on the image, pagefile and hiberfil.
4. Salvage tails of large files; carve deleted originals (HDD/VM disks).
5. VM disks, SQL Server data files and files locked during the run were
   probably not encrypted at all.
