rule threat_system_environment_read
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects reading of environment variables (requires import, often contain secrets)"
        identifies = "threat.system.environment.read"
        severity = "low"
        mitre_tactics = "credential-access"
        specificity = "low"
        sophistication = "low"

        max_hits = 3
        path_include = "*.py,*.pyx,*.pyi,*.go"
    strings:
        // Python - requires import os
        $py_os_environ = /\.environ\b/ nocase
        $py_os_getenv = /\.getenv\s*\(/ nocase

        // Go - requires import os
        $go_getenv = /os\.Getenv\s*\(/ nocase
        $go_environ = /os\.Environ\s*\(/ nocase
        $go_lookupenv = /os\.LookupEnv\s*\(/ nocase

    condition:
        any of them
}
