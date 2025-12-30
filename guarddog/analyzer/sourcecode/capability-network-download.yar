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
        path_include = "*.py,*.pyx,*.pyi,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs,*.go"
    strings:
        // Python - downloading
        $py_urlretrieve = "urllib.request.urlretrieve(" nocase
        $py_urlopen = "urllib.request.urlopen(" nocase
        $py_requests_get = "requests.get(" nocase
        $py_requests_download = "requests.download(" nocase
        $py_wget = "wget.download(" nocase

        // JavaScript/Node.js - downloading
        $js_https_get = /https?\.(get|request)\(/ nocase
        $js_axios = /axios\.(get|download)\(/ nocase
        $js_fetch = "fetch(" nocase
        $js_node_fetch = "node-fetch" nocase
        $js_got = "got(" nocase

        // Go - HTTP downloads
        $go_http_get = "http.Get(" nocase
        $go_http_do = "http.Do(" nocase
        $go_ioutil_readall = "io.ReadAll(" nocase

    condition:
        any of them
}
