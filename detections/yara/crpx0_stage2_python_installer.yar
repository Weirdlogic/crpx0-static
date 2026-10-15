/*
  CRPx0 stage 2: MinGW installer that downloads the python.org embeddable
  runtime into %TEMP%\<decoy folder>, unpacks it with tar.exe, pip-installs
  cryptography/requests/pywin32 and runs sys_service.py.
  Config strings are single-byte XOR with a per-build key, hence xor().
  Report: reports/crpx0/2026-10-15-28685dff00aa/report.md
*/

rule CRPX0_Stage2_Python_Installer
{
    meta:
        description = "CRPx0 stage-2 installer: decoy TEMP folder names, tar.exe unpack, XOR-encoded CRPX0_EMBEDDED / sys_service.py / python embed URL"
        author = "Weirdlogic research"
        date = "2026-10-15"
        reference_sha256 = "5856f684c90dba657f5cd77dd337d81fd7503b5225e1843341c1f483eebc9560"
        family = "CRPx0 (installer stage, written to disk as %LOCALAPPDATA%\\index.dll)"
        confidence = "high"

    strings:
        $d1 = "Low_Graphics_Cache" ascii
        $d2 = "Sys_Diagnostics" ascii
        $d3 = "Windows_Driver_Host" ascii
        $d4 = "Update_Temp_Store" ascii
        $d5 = "Cache_Sys" ascii
        $tar = "tar.exe -xf \"%s\" -C \"%s\"" ascii
        $x1 = "CRPX0_EMBEDDED" xor(1-255)
        $x2 = "\\sys_service.py" xor(1-255)
        $x3 = "python-3.10.11-embed-" xor(1-255)
        $x4 = "pip install cryptography requests pywin32" xor(1-255)

    condition:
        uint16(0) == 0x5A4D and
        (3 of ($d*) and $tar and 1 of ($x*)) or (2 of ($x*) and $tar)
}
