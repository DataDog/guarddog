rule capability_runtime_system
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects system information gathering capabilities"
        identifies = "capability.runtime.system"
        severity = "low"
        specificity = "low"
        sophistication = "low"
        max_hits = 1
        path_include = "*.py,*.pyx,*.pyi,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs"

    strings:
        // Python - system info
        $py_platform = "platform.system()" nocase
        $py_platform_machine = "platform.machine()" nocase
        $py_platform_node = "platform.node()" nocase
        $py_uname = "os.uname()" nocase
        $py_sysinfo = "platform.uname()" nocase
        $py_arch = "platform.architecture()" nocase
        $py_hostname = "socket.gethostname()" nocase
        $py_getuser = "getpass.getuser()" nocase

        // Node.js - system info
        $js_os_platform = "os.platform()" nocase
        $js_os_arch = "os.arch()" nocase
        $js_os_hostname = "os.hostname()" nocase
        $js_os_type = "os.type()" nocase
        $js_os_userinfo = "os.userInfo()" nocase
        $js_process_platform = "process.platform" nocase
        $js_process_arch = "process.arch" nocase

    condition:
        any of them
}
