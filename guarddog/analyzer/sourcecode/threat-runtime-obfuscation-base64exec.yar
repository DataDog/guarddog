rule threat_runtime_obfuscation_base64exec
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects base64 decoding followed by code execution"
        identifies = "threat.runtime.obfuscation.base64exec"
        severity = "high"
        mitre_tactics = "defense-evasion,execution"
        specificity = "medium"
        sophistication = "medium"

        max_hits = 1
        path_include = "*.py,*.pyx,*.pyi,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs,*.go"
    strings:
        // Python - base64 decode + exec/eval
        $py_b64decode = "base64.b64decode(" nocase
        $py_b64decode_alt = "base64.decodebytes(" nocase
        $py_b64decode_std = "base64.standard_b64decode(" nocase
        $py_exec = "exec(" nocase
        $py_eval = "eval(" nocase
        $py_compile = "compile(" nocase

        // JavaScript/Node.js - atob/Buffer + eval
        $js_atob = "atob(" nocase
        $js_buffer_from = "Buffer.from(" nocase
        $js_buffer_decode = ".toString(" nocase
        $js_eval = "eval(" nocase
        $js_function = "Function(" nocase

        // Go - base64 decode + exec
        $go_b64decode = "base64.StdEncoding.DecodeString(" nocase
        $go_b64decode_alt = "base64.URLEncoding.DecodeString(" nocase
        $go_exec = "exec.Command(" nocase

    condition:
        (any of ($py_b64decode*) and (any of ($py_exec, $py_eval, $py_compile))) or
        (($js_atob or ($js_buffer_from and $js_buffer_decode)) and ($js_eval or $js_function)) or
        (any of ($go_b64decode*) and $go_exec)
}
