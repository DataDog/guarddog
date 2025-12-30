rule capability_runtime_environment_read
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects reading of environment variables"
        identifies = "capability.runtime.environment.read"
        severity = "low"
        specificity = "low"
        sophistication = "low"

        max_hits = 1
        path_include = "*.py,*.pyx,*.pyi,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs,*.go"
    strings:
        // Python
        $py_os_environ = "os.environ" nocase
        $py_os_getenv = "os.getenv(" nocase
        $py_sys_env = "sys.env" nocase

        // JavaScript/Node.js
        $js_process_env = "process.env" nocase
        $js_env_var = /process\.env\[/ nocase
        $js_env_serialize = "JSON.stringify(process.env)" nocase

        // Go
        $go_getenv = "os.Getenv(" nocase
        $go_environ = "os.Environ(" nocase
        $go_lookupenv = "os.LookupEnv(" nocase

    condition:
        any of them
}
