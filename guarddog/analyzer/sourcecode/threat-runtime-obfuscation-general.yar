rule threat_runtime_obfuscation_general
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects various code obfuscation techniques"
        identifies = "threat.runtime.obfuscation.general"
        severity = "medium"
        mitre_tactics = "defense-evasion"
        specificity = "low"
        sophistication = "medium"

        max_hits = 1
        path_include = "*.py,*.pyx,*.pyi,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs"
    strings:
        // Python - hex/octal obfuscation (raised threshold to 30+ consecutive to skip crypto test vectors)
        $py_hex_chr = /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){29,}/ nocase
        $py_octal = /\\[0-7]{3}(\\[0-7]{3}){29,}/ nocase

        // JavaScript - JSFuck, packer
        $js_jsfuck = /\[\s*!\s*!\s*\[\s*\]\s*\]/ nocase
        $js_packer = /\beval\s*\(\s*\bfunction\s*\([a-z],\s*[a-z],\s*[a-z],\s*[a-z]/ nocase
        $js_fromcharcode = /\bString\s*\.\s*fromCharCode\s*\([^)]{20,}\)/ nocase
        $js_split_reverse = /\.(split|reverse)\(['"]['"]\)\.(join|reverse)\(/ nocase

        // JavaScript - basic bracket notation obfuscation (common in wild)
        $js_bracket_call = /\[[^\]]+\]\s*\.\s*\bcall\s*\(/ nocase
        $js_bracket_apply = /\[[^\]]+\]\s*\.\s*\bapply\s*\(/ nocase
        $js_bracket_bind = /\[[^\]]+\]\s*\.\s*\bbind\s*\(/ nocase

    condition:
        any of them
}
