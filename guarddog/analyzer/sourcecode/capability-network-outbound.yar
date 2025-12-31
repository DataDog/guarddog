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
        // Python - HTTP
        $py_requests = /requests\.(get|post|put|delete|head|patch)/
        $py_urllib = /urllib\.request\.(urlopen|urlretrieve|Request)/
        $py_http = /http\.client\.(HTTPConnection|HTTPSConnection)/
        $py_socket = /socket\.socket\([^)]*SOCK_STREAM/

        // Python - DNS
        $py_getaddrinfo = /socket\.getaddrinfo\s*\(/
        $py_gethostbyname = /socket\.gethostbyname/
        $py_gethostbyaddr = /socket\.gethostbyaddr/
        $py_dns_resolver = /dns\.resolver/

        // JavaScript/TypeScript - HTTP
        $js_fetch = /\bfetch\s*\(/
        $js_axios = /axios\.(get|post|put|delete|patch)/
        $js_http = /require\s*\(\s*['"]https?['"]\s*\)/
        $js_request = /\brequire\s*\(\s*['"]request['"]\s*\)/

        // JavaScript/TypeScript - DNS
        $js_dns_require = /require\s*\(\s*['"]dns['"]\s*\)/
        $js_dns_lookup = /\.(lookup|resolve4|resolve6|resolveMx|resolveTxt|resolveNs|resolveCname|resolveSrv|resolvePtr|resolveSoa|resolveNaptr)\s*\(/
        $js_dns_resolve = /\bresolve\s*\(/
        $js_dns_import = /import\s+.*\s+from\s+['"]dns['"]/

        // Go - HTTP
        $go_http = /http\.(Get|Post|Head|Do)\(/
        $go_client = /&?http\.Client\{/

        // Go - DNS
        $go_lookup = /net\.(LookupHost|LookupIP|LookupAddr|LookupCNAME|LookupMX|LookupNS|LookupTXT)\s*\(/

    condition:
        any of them
}
