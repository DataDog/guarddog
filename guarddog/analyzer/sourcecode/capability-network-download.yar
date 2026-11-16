rule capability_network_download
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects downloading files from network"
        identifies = "capability.network.download"
        severity = "low"
        specificity = "low"
        sophistication = "low"

        max_hits = 1
        path_include = "*.py,*.pyx,*.pyi,*.pth,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs,*.go"
    strings:
        // Python - downloading
        $py_urlretrieve = /urllib\.request\.urlretrieve\s*\(/ nocase
        $py_urlopen = /urllib\.request\.urlopen\s*\(/ nocase
        $py_requests_get = /\brequests\.get\s*\(/ nocase
        $py_requests_download = /\brequests\.download\s*\(/ nocase
        $py_wget = /\bwget\.download\s*\(/ nocase

        // Python - aliased imports, which hide the module name at the call site
        $py_requests_alias = /\bimport\s+requests\s+as\s+\w+/
        $py_requests_get_from_alias = /\bfrom\s+requests\s+import\s+get\s+as\s+\w+/
        $py_urllib_alias = /\bimport\s+urllib\.request\s+as\s+\w+/
        $py_urllib_from_alias = /\bfrom\s+urllib\.request\s+import\s+(urlopen|urlretrieve)\s+as\s+\w+/

        // JavaScript/Node.js - downloading
        $js_https_get = /https?\.(get|request)\b\s*\(/ nocase
        $js_axios = /axios\.(get|download)\b\s*\(/ nocase
        $js_fetch = /\bfetch\s*\(/ nocase
        $js_node_fetch = "node-fetch" nocase
        $js_got = /\bgot\s*\(/ nocase

        // Go - HTTP downloads
        $go_http_get = "http.Get(" nocase
        $go_http_do = "http.Do(" nocase
        $go_ioutil_readall = "io.ReadAll(" nocase

    condition:
        any of them
}
