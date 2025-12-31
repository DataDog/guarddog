private rule has_process_spawn
{
    strings:
        // Python - subprocess/os
        $py_subprocess = /subprocess\.(call|run|Popen|check_output)/ nocase
        $py_os_system = "os.system(" nocase
        $py_os_popen = "os.popen(" nocase

        // JavaScript
        $js_exec = /\b(exec|execSync|spawn|spawnSync)\b/ nocase
        $js_require_cp = /require\s*\(\s*['"]child_process['"]\s*\)/ nocase

        // Go - exec
        $go_exec = "exec.Command(" nocase

    condition:
        any of them
}

rule capability_network_lolbas
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects usage of LOLBAS network tools (curl, wget, nc, etc.)"
        identifies = "capability.network"
        severity = "low"
        specificity = "low"
        sophistication = "low"

        max_hits = 1
        path_include = "*.py,*.pyx,*.pyi,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs,*.go"
    strings:
        // Unix/Linux LOLBAS tools anywhere within strings
        $curl = /['"][^'"]*\bcurl\b[^'"]*['"]/ nocase
        $wget = /['"][^'"]*\bwget\b[^'"]*['"]/ nocase
        $nc = /['"][^'"]*\bnc\b[^'"]*['"]/ nocase
        $netcat = /['"][^'"]*\bnetcat\b[^'"]*['"]/ nocase
        $socat = /['"][^'"]*\bsocat\b[^'"]*['"]/ nocase

        // Windows LOLBAS tools anywhere within strings
        $certutil = /['"][^'"]*certutil[^'"]*['"]/ nocase
        $bitsadmin = /['"][^'"]*bitsadmin[^'"]*['"]/ nocase
        $powershell_web = /['"][^'"]*Invoke-WebRequest[^'"]*['"]/ nocase
        $powershell_rest = /['"][^'"]*Invoke-RestMethod[^'"]*['"]/ nocase

    condition:
        has_process_spawn and any of ($curl, $wget, $nc, $netcat, $socat,
                                       $certutil, $bitsadmin, $powershell_*)
}
