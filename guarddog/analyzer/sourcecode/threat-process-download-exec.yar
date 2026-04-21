rule threat_process_download_exec
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects download-and-execute patterns: fetching a remote file then executing it"
        identifies = "threat.process.spawn"
        severity = "high"
        mitre_tactics = "execution"
        specificity = "high"
        sophistication = "medium"
        max_hits = 3
        path_include = "*.py,*.pyx,*.pyi,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs"

    strings:
        // Python: os.system/popen with curl/wget piped or chained with execution
        $py_system_curl = /os\.(system|popen)\s*\(\s*['"f].*\bcurl\b/ nocase
        $py_system_wget = /os\.(system|popen)\s*\(\s*['"f].*\bwget\b/ nocase
        $py_system_start = /os\.(system|popen)\s*\(\s*['"f].*\bstart\s/ nocase
        $py_system_chmod = /os\.(system|popen)\s*\(\s*['"f].*\bchmod\b/ nocase

        // Python: subprocess with curl/wget
        $py_subprocess_curl = /subprocess\.\w+\(\s*\[?\s*['"]curl/ nocase
        $py_subprocess_wget = /subprocess\.\w+\(\s*\[?\s*['"]wget/ nocase

        // Python: subprocess with powershell (common malware delivery)
        $py_subprocess_ps = /subprocess\.\w+\(\s*\[?\s*['"]powershell/ nocase

        // Python: subprocess.call with shell script
        $py_subprocess_sh = /subprocess\.(call|run|Popen)\s*\(\s*['"]\.?\// nocase

        // Python: pip install inside code
        $py_pip_install = /subprocess\.\w+\(\s*\[?\s*['"]pip['"]\s*,?\s*['"]install/ nocase
        $py_os_pip = /os\.(system|popen)\s*\(\s*['"]pip\s+install/ nocase
        $py_import_pip = /pip\.(main|_internal\.cli\.main)\s*\(\s*\[['"]install/ nocase
        $py_pip_check_call = /check_call\s*\(\s*\[.*pip.*install/ nocase
        $py_pip_executable = /sys\.executable.*pip.*install/ nocase
        // from pip._internal import main; main(['install'...])
        $py_pip_from_import = /from\s+pip[\._].*import\s+main/ nocase
        $py_main_install = /\bmain\s*\(\s*\[['"]install/ nocase

        // Python: exec(compile(open())) - execute file content
        $py_exec_compile = /exec\s*\(\s*compile\s*\(\s*open\s*\(/ nocase

        // Python: download (requests/urllib) + exec/eval in same file
        $py_download_requests = /requests\.get\s*\(/ nocase
        $py_download_urllib = /urllib\.\w+\.urlopen\s*\(/ nocase
        $py_download_urlretrieve = /urllib\.\w+\.urlretrieve\s*\(/ nocase
        $py_exec = /\bexec\s*\(/ nocase
        $py_eval = /\beval\s*\(/ nocase

        // Python: download + subprocess.run([file_path]) - download binary then execute
        $py_subprocess_run = /subprocess\.(run|call|Popen)\s*\(/ nocase

        // Node.js: child_process.exec with curl/wget
        $js_exec_curl = /exec\s*\(\s*['"`].*\bcurl\b/ nocase
        $js_exec_wget = /exec\s*\(\s*['"`].*\bwget\b/ nocase

        // Node.js: fetch + eval
        $js_fetch_eval = /fetch\s*\(.*\).*\.then\s*\(.*eval/ nocase

        // Node.js: import child_process exec + fetch in same file
        $js_import_exec = /from\s+['"]child_process['"]\s*/ nocase
        $js_cp_exec = /child_process/ nocase
        $js_fetch = /\bfetch\s*\(\s*['"]https?:/ nocase

        // Shell download + execute chains
        $shell_curl_pipe = /curl\s+.*\|\s*(bash|sh|python|node|perl)\b/ nocase
        $shell_wget_pipe = /wget\s+.*-O\s*-\s*\|\s*(bash|sh|python|node|perl)\b/ nocase
        $shell_curl_exec = /curl\s+.*-o\s+\S+\s*&&\s*(chmod|\.\/|start|bash|sh)/ nocase
        $shell_wget_exec = /wget\s+.*-O\s+\S+\s*&&\s*(chmod|\.\/|start|bash|sh)/ nocase

        // PowerShell download patterns
        $ps_download = /powershell.*curl\.exe/ nocase
        $ps_iwr = /Invoke-WebRequest/ nocase
        $ps_downloadfile = /DownloadFile\s*\(/ nocase

    condition:
        // Direct download-execute patterns
        any of ($py_system_*, $py_subprocess_curl, $py_subprocess_wget, $py_subprocess_ps,
                $py_subprocess_sh, $py_pip_install, $py_os_pip, $py_import_pip,
                $py_pip_check_call, $py_pip_executable,
                $py_exec_compile, $js_*, $shell_*, $ps_*) or
        // from pip import main + main(['install'...])
        ($py_pip_from_import and $py_main_install) or
        // Download + exec/eval in same file
        (any of ($py_download_*) and any of ($py_exec, $py_eval)) or
        // Download + subprocess execution in same file (download binary + run it)
        (any of ($py_download_urlretrieve) and $py_subprocess_run) or
        // Node.js: child_process + fetch in same file (download + exec pattern)
        (any of ($js_import_exec, $js_cp_exec) and $js_fetch)
}
