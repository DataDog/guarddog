rule threat_npm_http_dependency
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects HTTP/HTTPS URL dependencies in package.json (dependency confusion, untrusted sources)"
        identifies = "threat.npm.http.dependency"
        severity = "high"
        mitre_tactics = "initial-access"
        specificity = "high"
        sophistication = "low"
        max_hits = 3
        path_include = "*/package.json,package.json"

    strings:
        // HTTP URL as dependency version (IP address or domain)
        $http_ip = /:\s*"https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ nocase
        $http_url = /:\s*"https?:\/\/[^"]+\.(tar\.gz|tgz|zip)"/ nocase
        // Generic HTTP dependency pointing to non-standard hosts
        $http_plain = /:\s*"http:\/\/[^"]+"/

    condition:
        any of them
}
