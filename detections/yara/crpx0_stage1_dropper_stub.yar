import "pe"

/*
  CRPx0 stage 1: MinGW dropper stub that decodes a 3.8 MB .data blob
  (xor k2 -> ror r -> not -> xor k1, per-build r and keys) into
  %LOCALAPPDATA%\<word>.dll (index/store/sync/core) and starts it with CREATE_NO_WINDOW.
  Report: reports/crpx0/2026-10-15-28685dff00aa/report.md
  Decoder: FUN_00401566 (28685dff...); EXE and DLL builds share the layout.
*/

rule CRPX0_Stage1_Dropper_Stub
{
    meta:
        description = "CRPx0 MinGW dropper stub: two 64-byte XOR key tables, byte-wise xor/ror/not/xor decoder, writes <word>.dll to LOCALAPPDATA"
        author = "Weirdlogic research"
        date = "2026-10-15"
        reference_sha256 = "28685dff00aa1752b62a8580955b2530d63092bdcc0528b872a668cddad78c11"
        family = "CRPx0 (dropper stage)"
        confidence = "high on the 7 known builds; the decoder idiom is generic, the string pair is not"

    strings:
        // drop name is chosen per build (index/store/sync/core.dll seen)
        $s_drop = /LOCALAPPDATA\x00{1,4}\\[a-z]{3,8}\.dll\x00/
        // key-table prep: movzx eax, byte ptr [K_xor]; xor edx, eax   (x2)
        $c_kx   = { 0F B6 05 ?? ?? ?? ?? 31 C2 }
        // per-byte loop: movzx eax, byte ptr [eax+K]; xor edx, eax
        $c_kb   = { 83 E0 3F 0F B6 80 ?? ?? ?? ?? 31 C2 }
        // not eax
        $c_not  = { 0F B6 00 F7 D0 }

    condition:
        uint16(0) == 0x5A4D and pe.is_32bit() and
        filesize > 3MB and filesize < 5MB and
        for any s in pe.sections : ( s.name == ".data" and s.raw_data_size > 3000000 ) and
        $s_drop and #c_kx >= 2 and #c_kb >= 2 and $c_not
}
