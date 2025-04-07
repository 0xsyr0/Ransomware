/*
C77L ransomware
*/


rule C77L
{
    meta:
        author = "rivitna"
        family = "ransomware.c77l"
        description = "C77L ransomware Windows payload"
        severity = 10
        score = 100

    strings:
        $s0 = " s | Encrypted Files : " ascii
        $s1 = "\nWaiting For Threads to be done..." ascii
        $s2 = "A Discord Webhook Client/1.0" wide
        $s3 = "\nEcrypted files count: " wide
        $s4 = " /TN \"Windows Update ALPHV\"" wide
        $s5 = "\x00timeout /t 2 /nobreak >nul\n\x00" wide
        $s6 = "sysinfo01.bios" wide
        $s7 = "Encrypt.LowerThan500KB" ascii wide
        $s8 = "Encrypt.Between500KBand500MB" ascii wide
        $s9 = "Encrypt.HigherThan500MB" ascii wide
        $s10 = "Wallpaper.ChangeDesktopWallpaper" ascii wide
        $s11 = "Hidden Mode.HiddenMode" ascii wide
        $s12 = "Special Path.EncryptOnlySpecialPath" ascii wide
        $s13 = "Special Path.SpecialPath" ascii wide
        $s14 = "Special Files.SpecialFilesExtentions" ascii wide
        $s15 = "Special Files.EncryptSpecialFilesFurther" ascii wide
        $s16 = "Files Group.EncryptGroup" ascii wide
        $s17 = "Network.SearchThroughNetwork" ascii wide
        $s18 = "Processes.KillRunningProcesses" ascii wide
        $s19 = "Log.DiscordLogMessage" ascii wide
        $s20 = "Files Group.FileGroup" ascii wide

    condition:
        ((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) and
        (
            (5 of ($s*))
        )
}
