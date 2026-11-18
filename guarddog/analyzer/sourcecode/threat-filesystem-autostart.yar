rule threat_filesystem_autostart
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects suspicious autostart persistence mechanisms"
        identifies = "threat.filesystem.autostart"
        severity = "high"
        mitre_tactics = "persistence"
        specificity = "high"
        sophistication = "medium"
        max_hits = 3
        path_include = "*.py,*.pyx,*.pyi,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs"

    strings:
        // Python - bashrc/profile modifications
        $py_bashrc = ".bashrc" nocase
        $py_bash_profile = ".bash_profile" nocase
        // Require quoted-path context so attribute access (self.profile,
        // config.profile) and identifiers (.profile_manager) don't match.
        $py_profile = /['"][^'"]*\.profile['"]/ nocase
        $py_zshrc = ".zshrc" nocase

        // Python - system-wide startup scripts
        $py_rc_local = "/etc/rc.local" nocase
        $py_init_d = "/etc/init.d/" nocase
        $py_profile_d = "/etc/profile.d/" nocase

        // Python - XDG autostart (Linux desktop)
        $py_autostart = ".config/autostart/" nocase

        // Python - LaunchAgent/LaunchDaemon (macOS)
        $py_launch_agents = "LaunchAgents" nocase
        $py_launch_daemons = "LaunchDaemons" nocase
        $py_plist = ".plist" nocase

        // Node.js - shell config file modifications
        $js_bashrc_write = /fs\.(writeFile|appendFile)[^)]*['"].*\.bashrc/ nocase
        $js_profile_write = /fs\.(writeFile|appendFile)[^)]*['"].*\.profile/ nocase
        $js_zshrc_write = /fs\.(writeFile|appendFile)[^)]*['"].*\.zshrc/ nocase

        // Node.js - startup directories
        $js_autostart_path = /['"].*\.config\/autostart/ nocase
        $js_init_path = /['"].*\/etc\/init\.d\// nocase

        // Windows Registry (Node.js on Windows)
        $win_run_key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $win_runonce_key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
        $win_startup_folder = "\\Start Menu\\Programs\\Startup" nocase

        // Python - Windows registry manipulation
        $py_winreg = "import winreg" nocase
        $py_reg_setvalue = "winreg.SetValueEx(" nocase

        // Combined patterns (file write + startup location)
        $py_write_mode = /'[wa]\+?'/ nocase
        // Word boundary so urlopen()/fdopen() don't satisfy the open() condition.
        $py_open_write = /\bopen\s*\(/ nocase

        // Python - .pth persistence: programmatically writing a .pth into
        // site-packages. site.py executes .pth import lines at every interpreter
        // startup, so a runtime .pth drop is self-installing persistence - the
        // same playbook as the .bashrc writes above. Payload content is not
        // required: writing any .pth into site-packages from library code is the
        // persistence mechanism regardless of content. The __editable___ exclusion
        // keeps setuptools editable installs (the only benign writer) out.
        // Accepted gap: an attacker naming their payload __editable___ evades this
        // arm - threat-runtime-autostart still catches the shipped file if present.
        $py_sitepackages = "site-packages" nocase
        $py_getsitepackages = "getsitepackages" nocase
        $py_pth_file = /['"][^'"]*\.pth['"]/ nocase
        $py_editable_marker = "__editable___" nocase

    condition:
        // Startup script modification patterns
        (any of ($py_bashrc, $py_bash_profile, $py_profile, $py_zshrc, $py_rc_local) and ($py_write_mode or $py_open_write)) or

        // System-wide startup locations
        any of ($py_init_d, $py_profile_d, $py_autostart) or

        // macOS persistence
        (any of ($py_launch_agents, $py_launch_daemons) and $py_plist) or

        // Node.js file writes to startup locations
        any of ($js_bashrc_write, $js_profile_write, $js_zshrc_write, $js_autostart_path, $js_init_path) or

        // Windows registry persistence
        (any of ($win_run_key, $win_runonce_key, $win_startup_folder) and (any of ($py_winreg, $py_reg_setvalue) or any of ($js_*))) or

        // .pth drop into site-packages (pypi only - gated via ecosystem external)
        (ecosystem == "pypi" and
         $py_pth_file and ($py_sitepackages or $py_getsitepackages) and
         ($py_write_mode or $py_open_write) and
         not $py_editable_marker)
}
