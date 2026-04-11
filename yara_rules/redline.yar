rule RedLine_Stealer
{
    meta:
        description = "RedLine Stealer 패턴 탐지"
        author      = "CAPEv2 Analyzer [CMR]"
        severity    = "critical"

    strings:
        $s1 = "Passwords" wide ascii nocase
        $s2 = "CreditCards" wide ascii nocase
        $s3 = "AutoFill" wide ascii nocase
        $s4 = "Telegram" wide ascii nocase
        $s5 = "Discord" wide ascii nocase
        $s6 = "Login Data" wide ascii nocase
        $s7 = "Web Data" wide ascii nocase
        $s8 = "wallet.dat" wide ascii nocase

        $net1 = "recordbreaker" nocase
        $net2 = "redline" nocase

        $api1 = "SQLite3" ascii
        $api2 = "GetClipboard" ascii nocase
        $api3 = "SystemInfo" ascii nocase

    condition:
        (4 of ($s*)) or
        (1 of ($net*) and 2 of ($s*)) or
        (2 of ($api*) and 3 of ($s*))
}
