rule capability_runtime_system
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects importing of system information modules"
        identifies = "capability.runtime.system"
        severity = "low"
        specificity = "low"
        sophistication = "low"
        max_hits = 1
        path_include = "*.py,*.pyx,*.pyi,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs,*.go"

    strings:
        // Python - import system modules
        $py_import_os = /import\s+os\b/ nocase
        $py_import_platform = /import\s+platform\b/ nocase
        $py_import_getpass = /import\s+getpass\b/ nocase
        $py_from_os = /from\s+os\s+import/ nocase
        $py_from_platform = /from\s+platform\s+import/ nocase
        $py_from_getpass = /from\s+getpass\s+import/ nocase

        // JavaScript - require/import system modules
        $js_require_os = /require\s*\(\s*['"]os['"]\s*\)/ nocase
        $js_import_os = /import\s+.*\s+from\s+['"]os['"]/ nocase
        $js_process = /\bprocess\.(platform|arch|env|version)\b/ nocase

        // Go - import system modules
        $go_import_runtime = /import\s+"runtime"/ nocase
        $go_import_os = /import\s+"os"/ nocase

    condition:
        any of them
}
