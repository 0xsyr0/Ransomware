/*
Enmity ransomware
*/


rule Enmity
{
    meta:
        author = "rivitna"
        family = "ransomware.enmity.windows"
        description = "Enmity ransomware Windows payload"
        severity = 10
        score = 100

    strings:
        $a0 = "\\Enmity\\Release\\Enmity.pdb" ascii
        $a1 = "\\Mammon\\Release\\Mammon.pdb" ascii
        $a2 = "\\lastbutnotleast\\Release\\lst.pdb" ascii
        $a3 = "C:\\Users\\LEGION\\Desktop\\New folder\\" ascii
        $a4 = "\x00\nMail:\x00\x00\nData" ascii
        $a5 = "CARE=\x00" ascii
        $a6 = "\x00space\x00\x00\x00create_directories\x00\x00current_path()\x00" ascii
        $a7 = "QWERTYUIOPASDFGHJKLMNBVCXZqwertyuiopasdfghjklz1234567890xcvbnm" ascii
        $a8 = "QWERTYUYUIOPLKJHGFDSAZXCVBNM1234567890" ascii
        $a9 = "Caught an unexpected exception. Continuing program..." ascii
        $a10 = "Failed to find first file in directory: " ascii
        $a11 = "Failed to open-\x00" ascii
        $a12 = { FF FF E8 03 10 00 0F 86 }
        $a13 = { 5D 00 49 00 44 00 2D 00 5B 00 00 00 ( 2D | 2E ) 00
                 4D 00 61 00 69 00 6C 00 ( 2D 00 5B | 5B ) 00 00 00 }
        $a14 = { 68 00 20 03 00 6A 01 8D 85 [2] F9 FF 50 E8 [3] 00 83 C4 10
                 [4-16] 68 00 20 03 00 8D ?5 [2] F9 FF }

    condition:
        ((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) and
        (
            (4 of ($a*))
        )
}
