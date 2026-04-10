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
        // Python - hex/octal obfuscation
        $py_hex_chr = /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){10,}/ nocase
        $py_octal = /\\[0-7]{3}(\\[0-7]{3}){10,}/ nocase
        $py_chr_array = /''\s*\.join\s*\(\s*\bchr\s*\(/ nocase
        $py_chr_loop = /\bchr\s*\(\s*[a-z]\s*\)\s*\bfor\s+[a-z]\s+\bin\b/ nocase

        // JavaScript - JSFuck, name mangling, packer
        $js_jsfuck = /\[\s*!\s*!\s*\[\s*\]\s*\]/ nocase
        $js_mangle = /_0x[a-f0-9]{4,6}/ nocase
        $js_packer = /\beval\s*\(\s*\bfunction\s*\([a-z],\s*[a-z],\s*[a-z],\s*[a-z]/ nocase
        $js_fromcharcode = /\bString\s*\.\s*fromCharCode\s*\([^)]{20,}\)/ nocase
        $js_split_reverse = /\.(split|reverse)\(['"]['"]\)\.(join|reverse)\(/ nocase

        // JavaScript - basic bracket notation obfuscation (common in wild)
        $js_bracket_call = /\[[^\]]+\]\s*\.\s*\bcall\s*\(/ nocase
        $js_bracket_apply = /\[[^\]]+\]\s*\.\s*\bapply\s*\(/ nocase
        $js_bracket_bind = /\[[^\]]+\]\s*\.\s*\bbind\s*\(/ nocase

        // Python - __builtins__ obfuscation (require getattr combo, not just the string)
        $py_getattr_builtins = /\bgetattr\s*\(\s*__builtins__/ nocase
        $py_getattr_exec = /\bgetattr\s*\([^,]+,\s*['"]exec['"]/ nocase

    condition:
        // Hex/octal obfuscation requires substantial sequences (10+ consecutive)
        any of ($py_hex_chr, $py_octal) or
        // chr join/loop patterns
        any of ($py_chr_array, $py_chr_loop) or
        // JavaScript obfuscation
        any of ($js_jsfuck, $js_mangle, $js_packer, $js_fromcharcode, $js_split_reverse) or
        any of ($js_bracket_call, $js_bracket_apply, $js_bracket_bind) or
        // Python builtins abuse (require actual dynamic access, not just the string)
        any of ($py_getattr_builtins, $py_getattr_exec)
}
