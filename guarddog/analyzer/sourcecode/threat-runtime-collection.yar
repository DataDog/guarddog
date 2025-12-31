rule threat_runtime_collection
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects active collection of system information (hostname, platform, architecture, user)"
        identifies = "threat.runtime.collection"
        severity = "low"
        mitre_tactics = "collection"
        specificity = "medium"
        sophistication = "low"

        max_hits = 3
        path_include = "*.py,*.pyx,*.pyi,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs,*.go"
    strings:
        // Python - unique system info function calls (object name doesn't matter)
        $py_system = /\.system\s*\(\s*\)/ nocase
        $py_machine = /\.machine\s*\(\s*\)/ nocase
        $py_node = /\.node\s*\(\s*\)/ nocase
        $py_uname = /\.uname\s*\(\s*\)/ nocase
        $py_architecture = /\.architecture\s*\(\s*\)/ nocase
        $py_gethostname = /\.gethostname\s*\(\s*\)/ nocase
        $py_getuser = /\.getuser\s*\(\s*\)/ nocase

        // JavaScript - unique system info function calls (object name doesn't matter)
        $js_platform = /\.platform\s*\(\s*\)/ nocase
        $js_arch = /\.arch\s*\(\s*\)/ nocase
        $js_hostname = /\.hostname\s*\(\s*\)/ nocase
        $js_type = /\.type\s*\(\s*\)/ nocase
        $js_userinfo = /\.userInfo\s*\(\s*\)/ nocase
        $js_release = /\.release\s*\(\s*\)/ nocase
        $js_version = /\.version\s*\(\s*\)/ nocase
        $js_homedir = /\.homedir\s*\(\s*\)/ nocase
        $js_tmpdir = /\.tmpdir\s*\(\s*\)/ nocase

        // Go - unique system info function calls
        $go_goos = /runtime\.GOOS\b/ nocase
        $go_goarch = /runtime\.GOARCH\b/ nocase
        $go_hostname = /os\.Hostname\s*\(\s*\)/ nocase
        $go_getenv = /os\.Getenv\s*\(/ nocase
        $go_user_current = /user\.Current\s*\(\s*\)/ nocase

    condition:
        any of them
}
