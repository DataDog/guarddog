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
        // Python - suspicious dynamic attribute access patterns
        // getattr with a variable (not a string literal) as the attribute name is more suspicious
        $py_dict_access = /__dict__\s*\[/ nocase
        $py_getattribute = "__getattribute__(" nocase
        $py_getattr_dynamic = /\bgetattr\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*,\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)/ nocase
        // getattr used to call exec/eval/compile/import dynamically
        $py_getattr_exec = /\bgetattr\s*\([^,]+,\s*['"](__import__|exec|eval|compile)['"]/ nocase

        // JavaScript - advanced introspection patterns (rarely used in legitimate code)
        $js_reflect_get = /\bReflect\s*\.\s*\bget\s*\(/ nocase
        $js_get_own_prop_desc = /\bObject\s*\.\s*getOwnPropertyDescriptor\s*\([^)]+,\s*[^)]+\)\s*\.\s*\bvalue\b/ nocase
        $js_get_own_prop_names = /\[\s*\bObject\s*\.\s*getOwnPropertyNames\s*\([^)]+\)\s*\.\s*\bfind\s*\(/ nocase
        $js_object_keys_find = /\[\s*\bObject\s*\.\s*\bkeys\s*\([^)]+\)\s*\.\s*\bfind\s*\(/ nocase
        $js_entries_find = /\bObject\s*\.\s*\bentries\s*\([^)]+\)\s*\.\s*\bfind\s*\([^)]+\)\s*\[\s*1\s*\]/ nocase
        $js_entries_filter = /\bObject\s*\.\s*\bentries\s*\([^)]+\)\s*\.\s*\bfilter\s*\([^)]+\)\s*\[\s*0\s*\]\s*\[\s*1\s*\]/ nocase

        // Go - reflect package for dynamic calls
        $go_reflect_call = /\breflect\s*\.\s*ValueOf\s*\(/ nocase
        $go_reflect_method = /\breflect\s*\.\s*Method\s*\(/ nocase

    condition:
        // Python: require dict access + getattr combo, or direct suspicious getattr
        ($py_dict_access and ($py_getattribute or $py_getattr_dynamic)) or
        $py_getattr_exec or
        // JavaScript: only fire on advanced introspection
        any of ($js_*) or
        // Go: reflect usage
        any of ($go_*)
