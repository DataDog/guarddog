rule threat_runtime_obfuscation
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects heavy obfuscation techniques commonly used by malware"
        identifies = "threat.runtime.obfuscation"
        severity = "low"
        mitre_tactics = "defense-evasion"
        specificity = "medium"
        sophistication = "low"

	path_include = "*.py,*.pyx,*.pyi,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs,*.go"
        max_hits = 1
    strings:
        // Base64 patterns (multiple long strings)
        $b64_1 = /[A-Za-z0-9+\/]{100,}={0,2}/

        // Hex-encoded strings
        $hex_1 = /\\x[0-9a-fA-F]{2}([\\x][0-9a-fA-F]{2}){20,}/

        // Unicode escape sequences
        $unicode_1 = /\\u[0-9a-fA-F]{4}(\\u[0-9a-fA-F]{4}){10,}/

        // Obfuscated variable names (randomized)
        $random_vars = /\b[a-zA-Z](_0x[a-f0-9]{4,6}|[A-Z]{10,})\b/

        // String concatenation obfuscation
        $concat = /['"]\s*\+\s*['"]/

    condition:
        (#b64_1 >= 5) or
        (#hex_1 >= 3) or
        (#unicode_1 >= 2) or
        (#random_vars >= 10 and #concat >= 20)
}
