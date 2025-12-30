rule threat_process_injection_dll
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects DLL injection, hijacking, and side-loading techniques"
        identifies = "threat.process.injection.dll"
        severity = "high"
        mitre_tactics = "defense-evasion,privilege-escalation,persistence"
        specificity = "high"
        sophistication = "high"

        max_hits = 5
        path_include = "*.py,*.pyx,*.pyi,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs"
    strings:
        // Windows API calls for DLL injection
        $win_writeprocessmemory = "WriteProcessMemory" nocase
        $win_createremotethread = "CreateRemoteThread" nocase
        $win_loadlibrary = "LoadLibraryA" nocase
        $win_loadlibraryex = "LoadLibraryExA" nocase
        $win_virtualalloc = "VirtualAllocEx" nocase
        $win_ntcreatethreadex = "NtCreateThreadEx" nocase

        // DLL proxy execution
        $dll_rundll32 = "rundll32" nocase
        $dll_regsvr32 = "regsvr32" nocase
        $dll_regasm = "regasm" nocase
        $dll_regsvcs = "regsvcs" nocase
        $dll_mshta = "mshta" nocase

        // LD_PRELOAD (Linux DLL equivalent)
        $linux_ld_preload = "LD_PRELOAD" nocase
        $linux_ld_library_path = "LD_LIBRARY_PATH" nocase

        // DLL file creation with executable
        $dll_ext = /\.(dll|so|dylib)['"]/ nocase
        $exe_ext = /\.(exe)['"]/ nocase

        // Python ctypes/CFFI for DLL loading
        $py_ctypes = "ctypes.WinDLL(" nocase
        $py_ctypes_load = "ctypes.CDLL(" nocase
        $py_windll = "ctypes.windll" nocase

        // JavaScript - node-ffi, edge.js
        $js_ffi = "ffi.Library(" nocase
        $js_edge = "edge.func(" nocase

    condition:
        2 of ($win_*) or
        any of ($dll_*) or
        ($linux_ld_preload or $linux_ld_library_path) or
        (($dll_ext or $exe_ext) and (any of ($win_*, $py_*, $js_*)))
}
