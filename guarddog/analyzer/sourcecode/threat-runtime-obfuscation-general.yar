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
        $py_chr_array = /''\s*\.join\s*\(\s*chr\s*\(/ nocase
        $py_chr_loop = /chr\s*\(\s*[a-z]\s*\)\s*for\s+[a-z]\s+in/ nocase

        // JavaScript - JSFuck, name mangling, packer
        $js_jsfuck = /\[\s*!\s*!\s*\[\s*\]\s*\]/ nocase
        $js_mangle = /_0x[a-f0-9]{4,6}/ nocase
        $js_packer = /eval\s*\(\s*function\s*\([a-z],\s*[a-z],\s*[a-z],\s*[a-z]/ nocase
        $js_fromcharcode = /String\.fromCharCode\s*\([^)]{20,}\)/ nocase
        $js_split_reverse = /\.(split|reverse)\(['"]['"]\)\.(join|reverse)\(/ nocase

        // Python - __builtins__ obfuscation
        $py_builtins_getattr = "__builtins__" nocase
        $py_getattr_exec = /getattr\s*\([^,]+,\s*['"]exec['"]/ nocase

    condition:
        any of them
}
