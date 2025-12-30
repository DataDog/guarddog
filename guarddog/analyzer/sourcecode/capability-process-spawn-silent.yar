rule capability_process_spawn_silent
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects silent process execution (hidden output, detached processes)"
        identifies = "capability.process.spawn.silent"
        severity = "medium"
        specificity = "medium"
        sophistication = "medium"

        max_hits = 1
        path_include = "*.py,*.pyx,*.pyi,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs,*.go"
    strings:
        // Python - subprocess with DEVNULL
        $py_devnull = "subprocess.DEVNULL" nocase
        $py_stdout_devnull = "stdout=subprocess.DEVNULL" nocase
        $py_stderr_devnull = "stderr=subprocess.DEVNULL" nocase
        $py_stdin_devnull = "stdin=subprocess.DEVNULL" nocase
        $py_stdout_pipe = "stdout=subprocess.PIPE" nocase

        // JavaScript/Node.js - detached + stdio ignore (both quoted and unquoted properties)
        $js_detached = /"?detached"?[\s]*:[\s]*true/ nocase
        $js_stdio_ignore = /"?stdio"?[\s]*:[\s]*('|")ignore/ nocase
        $js_stdio_arr_ignore = /"?stdio"?[\s]*:[\s]*\[[\s]*('|")ignore/ nocase
        $js_windowshide = /"?windowsHide"?[\s]*:[\s]*true/ nocase
        $js_unref = /\.unref\s*\(\s*\)/ nocase

        // Go - detached processes
        $go_setsid = "syscall.Setsid" nocase
        $go_hidewindow = "syscall.CREATE_NO_WINDOW" nocase

    condition:
        any of them
}
