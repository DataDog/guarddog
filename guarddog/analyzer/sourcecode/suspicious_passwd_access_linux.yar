rule suspicious_passwd_access_linux
{
    meta:
        author = "T HAMDOUNI, Datadog"
        description = "Detects suspicious read access to /etc/passwd file, which is often targeted by malware for credential harvesting"

    strings:
        $cli = /(cat|less|more|head|tail)\s+.{0,100}\/etc\/passwd/ nocase
        $read = /(readFile|readFileSync)\(\s*['"]\/etc\/passwd/ nocase
    condition:
        $cli or $read
}
