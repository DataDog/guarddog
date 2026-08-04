from guarddog.analyzer.analyzer import Analyzer
from guarddog.ecosystems import ECOSYSTEM


def test_rust_source_runs_applicable_yara_rules(tmp_path):
    source = tmp_path / "lib.rs"
    source.write_text("""\
use std::net::TcpStream;
use std::process::Command;

fn inspect_host() {
    let token = std::env::var("DEPLOY_TOKEN").unwrap();
    let socket = TcpStream::connect("example.com:443").unwrap();
    let process = Command::new("xmrig").spawn().unwrap();
    let endpoint = "https://webhook.site/collect";
}
""")
    rules = {
        "capability-network-outbound",
        "capability-process-spawn",
        "threat-network-exfiltration",
        "threat-process-cryptomining",
        "threat-runtime-environment-read",
    }

    result = Analyzer(ecosystem=ECOSYSTEM.CRATES).analyze_sourcecode(
        str(tmp_path), rules
    )

    assert result["errors"] == {}
    assert result["issues"] >= len(rules)
    assert all(result["results"][rule] for rule in rules)
