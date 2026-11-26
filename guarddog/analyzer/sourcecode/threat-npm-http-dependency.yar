rule threat_npm_http_dependency
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects package.json dependencies installed from a plain HTTP URL or from an HTTP/HTTPS URL pointing to an IP address or archive (dependency confusion, untrusted sources)"
        identifies = "threat.npm.http.dependency"
        severity = "high"
        mitre_tactics = "initial-access"
        specificity = "low"
        sophistication = "low"
        max_hits = 3
        path_include = "*/package.json,package.json"

    strings:
        // Candidate selection only. The rule matches any quoted http(s) URL; the
        // Analyzer then parses package.json (guarddog/analyzer/sourcecode/
        // npm_http_dependency.py) and reports only URLs used as dependency
        // specifiers in dependencies, devDependencies, optionalDependencies or
        // peerDependencies. Metadata URLs (homepage, author, contributors, test
        // configuration, ...) are not reported.
        $quoted_url = /"https?:\/\// nocase

    condition:
        $quoted_url
}
