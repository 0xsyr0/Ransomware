/*
TitanImposter (PolyVice) ransomware
*/


rule TitanImposter
{
    meta:
        author = "rivitna"
        family = "ransomware.titanimposter.windows"
        description = "TitanImposter ransomware Windows payload"
        severity = 10
        score = 100

    strings:
        $a1 = { 7C ?? 7F 07 3D 00 00 ?0 0? 76 0? [4-12] 7C ?? 7F 07
                3D 00 00 40 06 76 }
        $a2 = { 48 3D 00 00 50 00 0F 9F 85 [3] 00 48 3D 00 00 40 06
                0F 9F 85 [3] 00 7E }
        $a3 = "{{IDENTIFIER}}" ascii
        $a4 = "expand 32-byte kexpand 16-byte k" ascii
        $b1 = "EES401EP2" ascii
        $b2 = { 91 01 00 08 01 00 08 00 08 00 06 00 85 00 65 00 70 00 0B 00
                0A 00 06 00 01 00 02 10 }
        $c1 = "EES587EP1" ascii
        $c2 = { 4B 02 00 08 01 00 0A 00 0A 00 08 00 C4 00 9D 00 C0 00 0B 00
                0D 00 07 00 01 00 05 11 }

    condition:
        ((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) and
        (filesize < 300000) and
        (
            (2 of ($a*)) and ((1 of ($b*)) and (1 of ($c*)))
        )
}
