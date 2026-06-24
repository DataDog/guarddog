import json
import os
import tempfile

from guarddog.scanners.mcp_config_scanner import MCPConfigScanner


def _write_mcp_json(directory, servers):
    """Write a project-scoped .mcp.json config that discovery will find."""
    config = {"mcpServers": servers}
    path = os.path.join(directory, ".mcp.json")
    with open(path, "w") as f:
        json.dump(config, f)
    return path


def test_scan_local_detects_inline_secret():
    scanner = MCPConfigScanner()
    with tempfile.TemporaryDirectory() as tmpdir:
        _write_mcp_json(tmpdir, {
            "risky-server": {
                "command": "node",
                "args": ["server.js"],
                "env": {"API_KEY": "sk-abcdef1234567890"},
            }
        })
        result = scanner.scan_local(tmpdir)
        assert "issues" in result
        assert result["issues"] > 0
        assert "inline-secret-in-mcp-config" in result["results"]
        assert result["results"]["inline-secret-in-mcp-config"] is not None


def test_scan_local_detects_plaintext_http():
    scanner = MCPConfigScanner()
    with tempfile.TemporaryDirectory() as tmpdir:
        _write_mcp_json(tmpdir, {
            "http-server": {
                "url": "http://example.com/mcp",
            }
        })
        result = scanner.scan_local(tmpdir)
        assert result["issues"] > 0
        assert result["results"]["plaintext-http-mcp"] is not None


def test_scan_local_detects_shell_launcher():
    scanner = MCPConfigScanner()
    with tempfile.TemporaryDirectory() as tmpdir:
        _write_mcp_json(tmpdir, {
            "shell-server": {
                "command": "bash",
                "args": ["-c", "python server.py"],
            }
        })
        result = scanner.scan_local(tmpdir)
        assert result["issues"] > 0
        assert result["results"]["arbitrary-shell-launcher"] is not None


def test_scan_local_benign_config():
    """A .mcp.json is project-scoped so shared-project-mcp-config always fires.
    Verify that no *other* rules trigger for an otherwise benign config."""
    scanner = MCPConfigScanner()
    with tempfile.TemporaryDirectory() as tmpdir:
        _write_mcp_json(tmpdir, {
            "safe-server": {
                "command": "node",
                "args": ["./server.js"],
                "env": {"LOG_LEVEL": "info"},
            }
        })
        result = scanner.scan_local(tmpdir)
        assert "issues" in result
        # shared-project-mcp-config fires because .mcp.json is project-scoped
        findings = {k for k, v in result["results"].items() if v is not None}
        assert "inline-secret-in-mcp-config" not in findings
        assert "plaintext-http-mcp" not in findings
        assert "arbitrary-shell-launcher" not in findings


def test_scan_local_empty_directory():
    scanner = MCPConfigScanner()
    with tempfile.TemporaryDirectory() as tmpdir:
        result = scanner.scan_local(tmpdir)
        assert "issues" in result
        assert result["issues"] == 0
