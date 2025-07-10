/*
TitanImposter ransomware
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
        $a1 = { 7B 7B 49 44 45 4E 54 49 ( 46 | 46 49) 45 52 7D 7D }
        $a2 = "expand 32-byte kexpand 16-byte k" ascii
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
            (all of ($a*)) and ((1 of ($b*)) and (1 of ($c*)))
        )
}
