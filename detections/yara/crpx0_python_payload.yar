/*
  CRPx0 stage 3: the Python ransomware source as exec'd from memory, or as
  carved from memory / recovered from disk. Also matches the plaintext
  bootstrap (sys_service.py) that carries it base64(zlib()) encoded.
  Report: reports/crpx0/2026-10-15-28685dff00aa/report.md
*/

rule CRPX0_Python_Payload
{
    meta:
        description = "CRPx0 Python ransomware source: builder field names, .crpx0 extension, mutex stem, exfil multipart boundary"
        author = "Weirdlogic research"
        date = "2026-10-15"
        reference_sha256 = "752b8fe4e67803e15be65ac5d88be1b12d7d375ecb399cc96efa6f428e04fed2"
        family = "CRPx0"
        confidence = "high"

    strings:
        $a1 = "ENCRYPTED_EXT = '.crpx0'" ascii
        $a2 = "sys_lock_eb330e5d_" ascii
        $a3 = "----CrpxBoundary" ascii
        $a4 = "crpx0_debug.log" ascii
        $a5 = "def stage1_5_collect_samples" ascii
        $a6 = "ENCRYPTED_XOR_KEY = b\"gAAAAA" ascii
        $a7 = "SELF_EXCLUDE_TAG = 'excl_" ascii
        $a8 = "def domain_encrypt_network" ascii

    condition:
        filesize < 10MB and 4 of them
}

rule CRPX0_Bootstrap_Script
{
    meta:
        description = "CRPx0 sys_service.py bootstrap: chr()-joined builtins/base64/zlib, sets CRPX0_LOADER, exec(compile(zlib.decompress(b64decode(blob))))"
        author = "Weirdlogic research"
        date = "2026-10-15"
        family = "CRPx0 (bootstrap)"
        confidence = "high"

    strings:
        $env  = "os.environ['CRPX0_LOADER'] = '1'" ascii
        $b64  = "chr(98),chr(54),chr(52),chr(100),chr(101),chr(99),chr(111),chr(100),chr(101)" ascii  // b64decode
        $exec = "chr(101),chr(120),chr(101),chr(99)" ascii                                            // exec
        $blob = "= 'eNr" ascii

    condition:
        filesize < 10MB and $env and 2 of ($b64, $exec, $blob)
}
