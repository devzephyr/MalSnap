/*
    MalSnap Example YARA Rules
    Author: Adeyemi Folarin
    Description: Sample detection rules for common malware indicators
*/

rule Suspicious_High_Entropy
{
    meta:
        description = "Detects files with suspiciously high entropy (possible packing)"
        author = "MalSnap"
        severity = "medium"

    condition:
        math.entropy(0, filesize) > 7.0
}

rule Common_Packer_UPX
{
    meta:
        description = "Detects UPX packed executables"
        author = "MalSnap"
        reference = "https://upx.github.io/"
        severity = "low"

    strings:
        $upx1 = "UPX0"
        $upx2 = "UPX1"
        $upx3 = "UPX!"

    condition:
        uint16(0) == 0x5A4D and
        any of ($upx*)
}

rule Suspicious_Process_Injection
{
    meta:
        description = "Detects potential process injection capabilities"
        author = "MalSnap"
        severity = "high"

    strings:
        $api1 = "VirtualAllocEx" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "CreateRemoteThread" ascii
        $api4 = "OpenProcess" ascii

    condition:
        uint16(0) == 0x5A4D and
        3 of ($api*)
}

rule Potential_Keylogger
{
    meta:
        description = "Detects potential keylogging capabilities"
        author = "MalSnap"
        severity = "high"

    strings:
        $hook = "SetWindowsHookEx" ascii
        $key1 = "GetAsyncKeyState" ascii
        $key2 = "GetKeyState" ascii
        $key3 = "GetKeyboardState" ascii

    condition:
        uint16(0) == 0x5A4D and
        ($hook or 2 of ($key*))
}

rule Network_Download_Capability
{
    meta:
        description = "Detects network download capabilities"
        author = "MalSnap"
        severity = "medium"

    strings:
        $url1 = "URLDownloadToFile" ascii
        $url2 = "InternetOpen" ascii
        $url3 = "InternetConnect" ascii
        $url4 = "HttpOpenRequest" ascii
        $http = /https?:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}/

    condition:
        uint16(0) == 0x5A4D and
        (2 of ($url*) or $http)
}

rule Registry_Persistence
{
    meta:
        description = "Detects registry modification for persistence"
        author = "MalSnap"
        severity = "medium"

    strings:
        $reg1 = "RegSetValueEx" ascii
        $reg2 = "RegCreateKeyEx" ascii
        $run = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $runonce = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        any of ($reg*) and any of ($run*)
}

rule Anti_Debug_Techniques
{
    meta:
        description = "Detects anti-debugging techniques"
        author = "MalSnap"
        severity = "high"

    strings:
        $debug1 = "IsDebuggerPresent" ascii
        $debug2 = "CheckRemoteDebuggerPresent" ascii
        $debug3 = "NtQueryInformationProcess" ascii
        $debug4 = "OutputDebugString" ascii

    condition:
        uint16(0) == 0x5A4D and
        2 of them
}

rule Crypto_Ransomware_Indicators
{
    meta:
        description = "Detects potential ransomware indicators"
        author = "MalSnap"
        severity = "critical"

    strings:
        $crypt1 = "CryptEncrypt" ascii
        $crypt2 = "CryptDecrypt" ascii
        $crypt3 = "CryptAcquireContext" ascii

        $file1 = "FindFirstFile" ascii
        $file2 = "FindNextFile" ascii

        $ransom1 = "bitcoin" ascii wide nocase
        $ransom2 = "decrypt" ascii wide nocase
        $ransom3 = "ransom" ascii wide nocase
        $ransom4 = ".locked" ascii wide
        $ransom5 = ".encrypted" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        2 of ($crypt*) and
        2 of ($file*) and
        any of ($ransom*)
}

rule Suspicious_Embedded_PE
{
    meta:
        description = "Detects embedded PE files (droppers/loaders)"
        author = "MalSnap"
        severity = "high"

    strings:
        $mz = "MZ"

    condition:
        uint16(0) == 0x5A4D and
        #mz > 1
}

rule Command_And_Control_Indicators
{
    meta:
        description = "Detects potential C2 communication"
        author = "MalSnap"
        severity = "high"

    strings:
        $ip = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/
        $domain = /[a-zA-Z0-9\-]+\.(com|net|org|ru|cn|tk)/

        $socket1 = "WSAStartup" ascii
        $socket2 = "connect" ascii
        $socket3 = "send" ascii
        $socket4 = "recv" ascii

    condition:
        uint16(0) == 0x5A4D and
        ($ip or $domain) and
        3 of ($socket*)
}
