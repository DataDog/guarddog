rule threat_runtime_obfuscation_api
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects API call obfuscation using dynamic lookups"
        identifies = "threat.runtime.obfuscation.api"
        severity = "low"
        mitre_tactics = "defense-evasion"
        specificity = "low"
        sophistication = "medium"

        max_hits = 1
        path_include = "*.py,*.pyx,*.pyi,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs,*.go"
    strings:
        // Python - dynamic attribute access
        $py_dict_access = /__dict__\s*\[/ nocase
        $py_getattribute = "__getattribute__(" nocase
        $py_getattr = /getattr\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*,\s*['"]/ nocase
        $py_setattr = "setattr(" nocase

        // JavaScript - dynamic property access with strings
        $js_bracket_str = /\[['"][a-zA-Z_][a-zA-Z0-9_]*['"]\]\s*\(/ nocase
        $js_eval_prop = /\['[a-zA-Z]+'\]/ nocase

        // Go - reflect package for dynamic calls
        $go_reflect_call = "reflect.ValueOf(" nocase
        $go_reflect_method = "reflect.Method(" nocase

    condition:
        2 of them
}
