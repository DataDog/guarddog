rule capability_network_outbound
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects network request capabilities (HTTP, sockets, etc.)"
        identifies = "capability.network.outbound"
        severity = "low"
        specificity = "low"
        sophistication = "low"

        max_hits = 1
        path_include = "*.py,*.pyx,*.pyi,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs,*.go"
    strings:
        // Python
        $py_requests = /requests\.(get|post|put|delete|head|patch)/
        $py_urllib = /urllib\.request\.(urlopen|urlretrieve|Request)/
        $py_http = /http\.client\.(HTTPConnection|HTTPSConnection)/
        $py_socket = /socket\.socket\([^)]*SOCK_STREAM/

        // JavaScript/TypeScript
        $js_fetch = /\bfetch\s*\(/
        $js_axios = /axios\.(get|post|put|delete|patch)/
        $js_http = /require\s*\(\s*['"]https?['"]\s*\)/
        $js_request = /\brequire\s*\(\s*['"]request['"]\s*\)/

        // Go
        $go_http = /http\.(Get|Post|Head|Do)\(/
        $go_client = /&?http\.Client\{/

    condition:
        any of them
}
