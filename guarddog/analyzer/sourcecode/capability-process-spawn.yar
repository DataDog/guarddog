rule capability_process_spawn
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects process execution and spawning"
        identifies = "capability.process.spawn"
        severity = "low"
        specificity = "low"
        sophistication = "low"

        max_hits = 1
        path_include = "*.py,*.pyx,*.pyi,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs,*.go"
    strings:
        // Python - subprocess
        $py_subprocess_call = /subprocess\.(call|run|check_call|check_output|Popen)/ nocase
        $py_os_system = "os.system(" nocase
        $py_os_popen = "os.popen(" nocase
        $py_os_spawn = /os\.(spawn|exec)/ nocase
        $py_exec = /(^|\s)exec\s*\(/ nocase
        $py_eval = /(^|\s)eval\s*\(/ nocase

        // JavaScript/Node.js - child_process (both direct and destructured)
        $js_child_process = /child_process\.(exec|execSync|spawn|spawnSync|fork|execFile)/ nocase
        $js_require_child_process = /require\s*\(\s*['"]child_process['"]\s*\)/ nocase
        $js_spawn_destructure = /\{\s*(exec|execSync|spawn|spawnSync|fork|execFile)/ nocase
        $js_eval = /(^|\s|\()eval\s*\(/ nocase
        $js_function = "new Function(" nocase

        // Go - exec
        $go_exec_command = "exec.Command(" nocase
        $go_exec_commandcontext = "exec.CommandContext(" nocase
        $go_os_startprocess = "os.StartProcess(" nocase

    condition:
        any of them
}
