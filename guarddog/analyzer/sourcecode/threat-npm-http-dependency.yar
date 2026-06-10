rule threat_npm_http_dependency
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects HTTP/HTTPS URL dependencies in package.json (dependency confusion, untrusted sources)"
        identifies = "threat.npm.http.dependency"
        severity = "high"
        mitre_tactics = "initial-access"
        specificity = "low"
        sophistication = "low"
        max_hits = 3
        path_include = "*/package.json,package.json"

    strings:
        // HTTP URL as dependency version (IP address or domain)
        $http_ip = /:\s*"https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ nocase
        $http_url = /:\s*"https?:\/\/[^"]+\.(tar\.gz|tgz|zip)"/ nocase
        // Generic HTTP dependency pointing to non-standard hosts
        $http_plain = /:\s*"http:\/\/[^"]+"/
        // Plain-http URLs in package metadata fields (author/repo/homepage)
        $http_meta = /"(url|web|website|homepage|funding|bugs|email|wiki|blog|docs|documentation|repository|author|maintainers|contributors|logo|image)"\s*:\s*"http:\/\//  nocase

    condition:
        $http_ip or
        $http_url or
        // a plain-http value that is not a metadata field = a dependency URL
        (#http_plain > #http_meta)
}
