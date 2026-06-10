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
        // A long base64 run containing at least one base64-only character
        // (G-Z, g-z, +, /, =) so it can't match a pure hex literal (crypto constant).
        $b64_1 = /[A-Za-z0-9+\/]{40,}[G-Zg-z+\/=][A-Za-z0-9+\/]{40,}={0,2}/

        // Hex-encoded strings
        $hex_1 = /\\x[0-9a-fA-F]{2}([\\x][0-9a-fA-F]{2}){20,}/

        // Unicode escape sequences
        $unicode_1 = /\\u[0-9a-fA-F]{4}(\\u[0-9a-fA-F]{4}){10,}/

        // Hex-suffixed identifiers emitted by JS obfuscators (e.g. _0x3f2a)
        $random_vars = /\b_0x[a-f0-9]{4,6}\b/

        // String concatenation obfuscation
        $concat = /['"]\s*\+\s*['"]/

    condition:
        $b64_1 or
        (#hex_1 >= 3) or
        (#random_vars >= 10 and #concat >= 20) or
        // \uXXXX runs recur in legitimate Unicode/charset tables, so require a
        // second obfuscation signal alongside them
        (#unicode_1 >= 2 and ($b64_1 or #concat >= 5 or #hex_1 >= 1))
}
