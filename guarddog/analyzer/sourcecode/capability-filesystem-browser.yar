rule capability_filesystem_browser
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects browser credential and cookie access capabilities"
        identifies = "capability.filesystem.browser"
        severity = "medium"
        specificity = "high"
        sophistication = "low"
        max_hits = 1
        path_include = "*.py,*.pyx,*.pyi,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs"

    strings:
        // Python - Chrome/Chromium credential paths
        $py_chrome_login = "Login Data" nocase
        $py_chrome_cookies = "Cookies" nocase
        $py_chrome_path = /Chrome.*User Data/ nocase

        // Python - Firefox credential paths
        $py_firefox_logins = "logins.json" nocase
        $py_firefox_key4 = "key4.db" nocase
        $py_firefox_cookies = "cookies.sqlite" nocase
        $py_firefox_path = ".mozilla/firefox" nocase

        // Python - Safari paths (macOS)
        $py_safari_cookies = "Cookies.binarycookies" nocase
        $py_safari_keychain = "Safari/LocalStorage" nocase

        // Python - Edge paths
        $py_edge_path = "Microsoft\\Edge\\User Data" nocase

        // Python - credential extraction libraries
        $py_sqlite3 = "import sqlite3" nocase

        // Node.js - Chrome/Chromium paths
        $js_chrome_login = /'Login Data'|"Login Data"/ nocase
        $js_chrome_cookies = /'Cookies'|"Cookies"/ nocase
        $js_chrome_userdata = /['"].*Chrome.*User Data/ nocase

        // Node.js - Firefox paths
        $js_firefox_logins = /'logins\.json'|"logins\.json"/ nocase
        $js_firefox_cookies = /'cookies\.sqlite'|"cookies\.sqlite"/ nocase
        $js_firefox_path = /['"]\\.mozilla\/firefox/ nocase

        // Node.js - browser credential libraries
        $js_chrome_cookies_lib = "chrome-cookies-secure" nocase
        $js_electron_cookies = "electron-cookies" nocase

        // Node.js - SQLite access (common for browser DBs)
        $js_sqlite3 = "require('sqlite3')" nocase
        $js_better_sqlite = "better-sqlite3" nocase

    condition:
        // Browser-specific path access
        any of ($py_chrome_*, $py_firefox_*, $py_safari_*, $py_edge_*) or
        any of ($js_chrome_*, $js_firefox_*) or

        // Browser credential libraries
        any of ($js_chrome_cookies_lib, $js_electron_cookies) or

        // Combination: SQLite + browser paths
        (($py_sqlite3 or any of ($js_sqlite3, $js_better_sqlite)) and
         (any of ($py_chrome_login, $py_chrome_cookies, $py_firefox_logins, $py_firefox_cookies) or
          any of ($js_chrome_login, $js_chrome_cookies, $js_firefox_logins, $js_firefox_cookies)))
}
