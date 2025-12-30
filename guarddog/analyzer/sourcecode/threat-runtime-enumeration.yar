rule threat_runtime_enumeration
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects extensive system/network enumeration activities"
        identifies = "threat.runtime.enumeration"
        severity = "medium"
        mitre_tactics = "discovery"
        specificity = "medium"
        sophistication = "medium"
        max_hits = 3
        path_include = "*.py,*.pyx,*.pyi,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs"

    strings:
        // Python - process enumeration
        $py_psutil_process = "psutil.process_iter()" nocase
        $py_psutil_pids = "psutil.pids()" nocase
        $py_proc_list = "/proc/" nocase

        // Node.js - process enumeration
        $js_ps_list = "ps-list" nocase
        $js_process_list = "process-list" nocase
        $js_find_process = "find-process" nocase

        // Python - network interface enumeration
        $py_netifaces = "netifaces.interfaces()" nocase
        $py_ifconfig = "ifconfig" nocase
        $py_ip_addr = "ip addr" nocase

        // Node.js - network enumeration
        $js_os_networkinterfaces = "os.networkInterfaces()" nocase
        $js_network_list = "network-list" nocase

        // Python - user enumeration
        $py_etc_passwd = "/etc/passwd" nocase
        $py_pwd_getpwall = "pwd.getpwall()" nocase

        // Port scanning indicators
        $port_scan = /port.{1,10}scan/i nocase
        $nmap = "nmap" nocase

    condition:
        2 of them
}
