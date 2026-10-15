/*
  Triage rule for files encrypted by CRPx0 (IR / recovery scoping, not
  prevention): u32 RSA blob length 512 (RSA-4096), then u64 token length,
  then a Fernet token (base64url of 0x80 || ts -> "gAAAAA"), then the
  unencrypted remainder of the original file.
  Report: reports/crpx0/2026-10-15-28685dff00aa/report.md (Recovery options)
*/

rule CRPX0_Encrypted_File
{
    meta:
        description = "File in the CRPx0 .crpx0 format: 512-byte RSA-OAEP blob + Fernet token of the first 1 MiB + plaintext tail"
        author = "Weirdlogic research"
        date = "2026-10-15"
        family = "CRPx0 (encrypted output)"
        confidence = "high for the format; validated on synthetic fixtures only"

    condition:
        filesize > 600 and
        uint32(0) == 512 and
        uint32(520) == 0 and                       // high dword of the u64 token length
        uint32(516) > 56 and uint32(516) <= 1398200 and
        uint32(516) + 524 <= filesize and
        uint32be(524) == 0x67414141 and            // "gAAA"
        uint16be(528) == 0x4141                    // "AA"
}
