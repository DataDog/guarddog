rule threat_runtime_obfuscation_api
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects advanced API call obfuscation using introspection and reflection techniques"
        identifies = "threat.runtime.obfuscation.api"
        severity = "medium"
        mitre_tactics = "defense-evasion"
        specificity = "high"
        sophistication = "medium"

        max_hits = 1
        path_include = "*.py,*.pyx,*.pyi,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs,*.go"
    strings:
        // Python - dynamic attribute access
        $py_dict_access = /__dict__\s*\[/ nocase
        $py_getattribute = "__getattribute__(" nocase
        $py_getattr = /\bgetattr\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*,\s*['"]/ nocase
        $py_setattr = /\bsetattr\s*\(/ nocase

        // JavaScript - basic dynamic property access (kept for backward compatibility)
        $js_bracket_str = /\[['"][a-zA-Z_][a-zA-Z0-9_]*['"]\]\s*\(/ nocase
        $js_eval_prop = /\['[a-zA-Z]+'\]/ nocase

        // JavaScript - advanced introspection patterns (rarely used in legitimate code)
        // Reflect API for property access
        $js_reflect_get = /\bReflect\s*\.\s*\bget\s*\(/ nocase

        // Object introspection methods
        $js_get_own_prop_desc = /\bObject\s*\.\s*getOwnPropertyDescriptor\s*\([^)]+,\s*[^)]+\)\s*\.\s*\bvalue\b/ nocase
        $js_get_own_prop_names = /\[\s*\bObject\s*\.\s*getOwnPropertyNames\s*\([^)]+\)\s*\.\s*\bfind\s*\(/ nocase
        $js_object_keys_find = /\[\s*\bObject\s*\.\s*\bkeys\s*\([^)]+\)\s*\.\s*\bfind\s*\(/ nocase

        // Object.entries with find/filter for dynamic access
        $js_entries_find = /\bObject\s*\.\s*\bentries\s*\([^)]+\)\s*\.\s*\bfind\s*\([^)]+\)\s*\[\s*1\s*\]/ nocase
        $js_entries_filter = /\bObject\s*\.\s*\bentries\s*\([^)]+\)\s*\.\s*\bfilter\s*\([^)]+\)\s*\[\s*0\s*\]\s*\[\s*1\s*\]/ nocase

        // Go - reflect package for dynamic calls
        $go_reflect_call = /\breflect\s*\.\s*ValueOf\s*\(/ nocase
        $go_reflect_method = /\breflect\s*\.\s*Method\s*\(/ nocase

    condition:
        any of them
}
