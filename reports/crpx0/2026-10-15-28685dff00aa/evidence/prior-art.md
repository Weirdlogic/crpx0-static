# Prior art check: CRPx0 (read 2026-10-15)

Sources were read as untrusted text; quotes kept short. "Covered" means the
point is already public.

## Sources

| Source | What it covers for this sample |
|---|---|
| Ransom-ISAC Research Team, "CRPx0 ClickFix Ransomware Analysis", 2026-08-27 (Dani Z, Ellis Stannard, Eric Taylor, Nick Smart, Rakesh Krishnan, Yashraj Solanki; with Bridewell, Barricade Cyber Solutions, Crystal Intelligence), https://ransom-isac.org/blog/crpx0-clickfix-ransomware-analysis/ | The most complete prior work; covers most of the chain on other builds (affiliates 1 and 20; ClickFix HTML, stager DLL with `g_*` exports, `data.dll`, standalone DLL/EXE of 2026-07-29/31). Covered: MinGW stager with ~3.87 MB `.data`, xor-k2 / "ROL 1" / NOT / xor-k1 decoder; loader with XOR `0x52` config and XOR `0xE0` bootstrap at `.data+0x260`; tar.exe / Shell.Application; the five decoy TEMP folders; tor2web suffix list; base64+zlib+exec bootstrap; `_init_crypto()` Fernet-wrapped XOR key and `dx()`; C2 `207.180.29[.]236:8080/relay[.]php`, onion `/api[.]php`, token `crpx0_c2_2026`; Tox/Session/onions; Fernet + RSA-4096; file layout; first-1 MB partial encryption with cleartext tail; exfil ZIP in 512 KB chunks over plain HTTP; all anti-analysis function names; fodhelper; explorer.exe injection; lateral movement described as functional; per-build expiry kill switch (`0x6A77C2FF` in the standalone EXE; `Date.now()` in lures); 11 YARA rules + Sigma. Lists the seven 2026-08-04 MalwareBazaar builds analysed here (and `captcha_obf.html`) as "unanalysed by us" and "the best available independent test corpus" for their rules. The MalwareBazaar reporter of 28685dff… (`RakeshKrish12`) appears to be one of the authors. |
| ProVendata, "CRPxO Ransomware: Attack Chain, IOCs, and MITRE ATT&CK TTPs", https://www.provendata.com/blog/crpxo-ransomware | Lists 28685dff… as the "Affiliate EXE stager"; DLL drop to `%LOCALAPPDATA%\sync.dll`/`index.dll`; tar.exe; Fernet/RSA-4096/first-1 MB (ClickFix build); mutex pattern; `OneDrive Sync Maintenance`; lateral movement; leak sites `crpx0[.]su`, `crpxoxo[.]pw`. Attributes CryptoGuard/CryptoUpdate persistence to builder output. |
| TheRavenFile, Daily-Hunt "CRPX0 Ransomware" (cited in the MalwareBazaar comment) | IOC list: three onions incl. the C2 onion, Tox, Session, leak domains, 23.224.4[.]114–118, MD5s. |
| KELA, Fortra, Aryaka, The Register, Bitdefender (search summaries) | Actor history, victimology, lures, leak-site credibility. |
| ThreatFox `search_ioc`, 2026-10-15 | no result for the C2 IP, IP:port, C2 onion, `crpx0[.]su`. |

## Independent test of the Ransom-ISAC YARA rules on the corpus they flagged

Rules extracted from the article's code block (11 rules). Two mechanical
fixes only, no logic change: em dash characters (U+2014) replaced by `-` in two `for` ranges
(page typography), and `hash_[REDACTED]` meta keys renamed (not valid
identifiers). Rule text is theirs and is not republished here.
Result file: `crosssample/risac_rules_test.json`.

| Our files (7 builds) | Their rules that fire |
|---|---|
| stage 1, 3 DLL builds | `CRPx0_Stager_DLL`, `CRPx0_Standalone_Loader_PE`, 3/3 |
| stage 1, 4 EXE builds | none, 0/4 (no exports, no `sys_xxxxxxxx` string; `Stager_DLL` needs `is_dll`) |
| stage 2, 3 DLL builds | `CRPx0_Loader_DLL`, 3/3 |
| stage 2, 4 EXE builds | none, 0/4 (`Loader_DLL` requires `pe.is_dll()`) |
| bootstrap (`sys_service.py`) | none, 0/7 (`Python_Loader_Packed` needs literal `exec`/`compile`; these build them with `chr()`) |
| stage 3 Python | `CRPx0_Ransomware_Python`, 7/7 |
| synthetic `.crpx0` files (ours) | `CRPx0_Encrypted_File_Header`, 10/10 |

## What this report adds (not found in the sources above)

1. The seven 2026-08-02 builds, decoded end to end (stage 1 → 2 → bootstrap → 3 → config) with generic decoders, and what changes per build: ROR amount (1, 2, 4, 6, 7, their "ROL 1" is ROR 7, the 0dc6a5ce variant), both stage-2 XOR keys, drop name (`index`/`store`/`sync`/`core.dll`), OPERATION_ID, keys, tags. Affiliate 21 (they report 1 and 20).
2. Builder timeline: OPERATION_ID = Fernet token timestamp = build time; stage 2 compiled +16–19 s, stage 1 +35–39 s; 7 builds in 76 minutes.
3. Recovery path: the per-victim Fernet key is POSTed in clear JSON (`decryption_key`) over plain HTTP before and after encryption; one captured request decrypts the whole host. Their code comment says the victim "can never recover without private key". Clean-room decryptor + key hunter, validated on synthetic files.
4. Lateral movement cannot run in these builds: `key.encode()` on `bytes` raises `AttributeError` before discovery (they describe the phase as functional).
5. IsDebuggerPresent check and AMSI patch are dead code: three hard-coded lists decode with no key and are identical across builds (they list both as working).
6. UAC bypass is unlikely to elevate (inferred): the key is `ms-settings\shell\open<6 hex>\command`, not `open`; their table shows `shell\open\command`.
7. No expiry kill switch in the stub, stage 2 or stage 3 of these builds: `GetSystemTime`/`GetTickCount` in the stub feed only junk arithmetic (they report expiry checks in other builds).
8. Stage-2 sandbox gates that stall with `Sleep(INFINITE)`: debugger, NtGlobalFlag, < 2 CPUs, uptime < 5 min, RAM < 1.5 GiB, C:\ < 50 GiB.
9. Ransom wallpaper made with ChatGPT (C2PA manifest: claim generator ChatGPT, `softwareAgent` GPT-4o, `trainedAlgorithmicMedia`; signature not verified).
10. Rule coverage: their published rules miss the 4 EXE builds (stages 1–2) and all bootstraps; ours cover 7/7 per class with 0 hits on 47,483 local benign files.

Independently confirmed (already public, reproduced here byte for byte): the C2 relay URLs and token, the Fernet-wrapped XOR key, the file format and 1 MiB partial encryption.
