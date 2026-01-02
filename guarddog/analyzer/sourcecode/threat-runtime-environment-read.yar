rule threat_runtime_environment_read
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects reading of environment variables via runtime globals (no import needed)"
        identifies = "threat.runtime.environment.read"
        severity = "low"
        mitre_tactics = "credential-access"
        specificity = "low"
        sophistication = "low"

        max_hits = 3
        path_include = "*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs"
    strings:
        // JavaScript/Node.js - credential-related env vars
        $js_env_api_key = /process\.env\.[A-Z_]*API[_]?KEY[A-Z_]*/ nocase
        $js_env_secret = /process\.env\.[A-Z_]*SECRET[A-Z_]*/ nocase
        $js_env_token = /process\.env\.[A-Z_]*TOKEN[A-Z_]*/ nocase
        $js_env_password = /process\.env\.[A-Z_]*PASS(WORD)?[A-Z_]*/ nocase
        $js_env_auth = /process\.env\.[A-Z_]*AUTH[A-Z_]*/ nocase
        $js_env_key = /process\.env\.[A-Z_]+KEY\b/ nocase
        $js_env_creds = /process\.env\.[A-Z_]*(CREDENTIAL|CRED)[A-Z_]*/ nocase

        // Serializing entire environment (exfiltration risk)
        $js_env_serialize = "JSON.stringify(process.env)" nocase

    condition:
        any of them
}
