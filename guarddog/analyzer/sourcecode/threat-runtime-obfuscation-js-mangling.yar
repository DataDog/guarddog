rule threat_runtime_obfuscation_js_mangling
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects JavaScript variable name mangling (_0x pattern) used by obfuscation tools"
        identifies = "threat.runtime.obfuscation.js.mangling"
        severity = "medium"
        mitre_tactics = "defense-evasion"
        specificity = "medium"
        sophistication = "medium"
        max_hits = 1
        path_include = "*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs"
        path_exclude = "*.min.js,*.bundle.js,dist/*,build/*,vendor/*,node_modules/*"

    strings:
        // _0x hex variable names are the signature of javascript-obfuscator and similar tools
        // Require multiple unique instances to avoid matching one-off var names
        $hex_var_1 = /_0x[a-f0-9]{4,6}\b/
        $hex_var_2 = /const _0x[a-f0-9]{4,6}\s*=/
        $hex_var_3 = /function _0x[a-f0-9]{4,6}\s*\(/
        $hex_var_4 = /var _0x[a-f0-9]{4,6}\s*=/

    condition:
        3 of them
}
