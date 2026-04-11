rule Ransomware_Generic
{
    meta:
        description = "랜섬웨어 일반 패턴 탐지"
        author      = "CAPEv2 Analyzer [CMR]"
        severity    = "critical"

    strings:
        $ransom1 = "YOUR FILES HAVE BEEN ENCRYPTED" nocase wide ascii
        $ransom2 = "DECRYPT" nocase wide ascii
        $ransom3 = "bitcoin" nocase wide ascii
        $ransom4 = "ransomware" nocase wide ascii
        $ransom5 = "HOW TO RECOVER" nocase wide ascii
        $ransom6 = "README" nocase wide ascii
        $ransom7 = ".onion" nocase wide ascii

        $ext1 = ".locked" nocase
        $ext2 = ".enc" nocase
        $ext3 = ".crypt" nocase
        $ext4 = ".encrypted" nocase
        $ext5 = ".readme" nocase

        $api1 = "CryptEncrypt" ascii
        $api2 = "CryptGenKey" ascii
        $api3 = "BCryptEncrypt" ascii
        $api4 = "vssadmin" nocase ascii
        $api5 = "shadow" nocase ascii

        $wiper1 = "delete shadows" nocase
        $wiper2 = "resize shadowstorage" nocase

    condition:
        (3 of ($ransom*)) or
        (2 of ($ransom*) and 1 of ($ext*)) or
        (2 of ($api*) and 2 of ($ransom*)) or
        (1 of ($wiper*) and 2 of ($ransom*))
}

rule Ransomware_LockBit_Pattern
{
    meta:
        description = "LockBit 계열 랜섬웨어 패턴"
        author      = "CAPEv2 Analyzer [CMR]"
        severity    = "critical"

    strings:
        $lb1 = "LockBit" nocase wide ascii
        $lb2 = "lockbit" nocase
        $lb3 = "Restore-My-Files" nocase
        $lb4 = "lock_icon" nocase
        $lb5 = ".lockbit" nocase

    condition:
        2 of them
}
