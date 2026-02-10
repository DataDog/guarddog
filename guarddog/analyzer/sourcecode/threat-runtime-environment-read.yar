rule threat_runtime_environment_read
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects reading of environment variables (credential access, often contains secrets)"
        identifies = "threat.runtime.environment.read"
        severity = "low"
        mitre_tactics = "credential-access"
        specificity = "low"
        sophistication = "low"

        max_hits = 3
        path_include = "*.py,*.pyx,*.pyi,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs,*.go,*.rb,*.gemspec"
    strings:
        // JavaScript/Node.js - credential-related env vars (process.env is runtime global)
        $js_env_api_key = /process\.env\.[A-Z_]*API[_]?KEY[A-Z_]*/ nocase
        $js_env_secret = /process\.env\.[A-Z_]*SECRET[A-Z_]*/ nocase
        $js_env_token = /process\.env\.[A-Z_]*TOKEN[A-Z_]*/ nocase
        $js_env_password = /process\.env\.[A-Z_]*PASS(WORD)?[A-Z_]*/ nocase
        $js_env_auth = /process\.env\.[A-Z_]*AUTH[A-Z_]*/ nocase
        $js_env_key = /process\.env\.[A-Z_]+KEY\b/ nocase
        $js_env_creds = /process\.env\.[A-Z_]*(CREDENTIAL|CRED)[A-Z_]*/ nocase

        // Serializing entire environment (exfiltration risk)
        $js_env_serialize = "JSON.stringify(process.env)" nocase

        // Python - environment access (object name agnostic)
        $py_environ = /\.environ\b/ nocase
        $py_getenv = /\.getenv\s*\(/ nocase

        // Go - environment access (object name agnostic)
        $go_getenv = /\.Getenv\s*\(/ nocase
        $go_environ = /\.Environ\s*\(/ nocase
        $go_lookupenv = /\.LookupEnv\s*\(/ nocase

        // Ruby - ENV serialization (exfiltration risk)
        $rb_env_to_h_json = /\bENV\s*\.\s*to_h\s*\.\s*to_json/ nocase
        $rb_env_to_hash_json = /\bENV\s*\.\s*to_hash\s*\.\s*to_json/ nocase
        $rb_json_dump_env = /\bJSON\s*\.\s*dump\s*\(\s*\bENV/ nocase
        $rb_json_generate_env = /\bJSON\s*\.\s*generate\s*\(\s*\bENV/ nocase
        $rb_env_to_h_yaml = /\bENV\s*\.\s*to_h\s*\.\s*to_yaml/ nocase
        $rb_env_to_hash_yaml = /\bENV\s*\.\s*to_hash\s*\.\s*to_yaml/ nocase
        $rb_yaml_dump_env = /\bYAML\s*\.\s*dump\s*\(\s*\bENV/ nocase
        $rb_marshal_dump_env = /\bMarshal\s*\.\s*dump\s*\(\s*\bENV/ nocase
        $rb_env_inspect = /\bENV\s*\.\s*inspect/ nocase
        $rb_env_to_h_inspect = /\bENV\s*\.\s*to_h\s*\.\s*inspect/ nocase
        $rb_env_to_hash_inspect = /\bENV\s*\.\s*to_hash\s*\.\s*inspect/ nocase

    condition:
        any of them
}
