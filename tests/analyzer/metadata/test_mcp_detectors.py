import pytest

from guarddog.analyzer.metadata.mcp import (
    MCP_METADATA_RULES,
    ArbitraryShellLauncher,
    DangerousToolSurface,
    FloatingPackageLauncher,
    InlineSecretInMCPConfig,
    OverbroadFilesystemAccess,
    PlaintextHTTPMCP,
    SharedProjectMCPConfig,
)


def _make_info(*servers):
    return {"servers": list(servers)}


def _server(**kwargs):
    base = {"server_name": "test-server", "source_path": "/tmp/mcp.json"}
    base.update(kwargs)
    return base


class TestInlineSecretInMCPConfig:
    detector = InlineSecretInMCPConfig()

    def test_detects_secret_key_in_env(self):
        info = _make_info(_server(env={"API_KEY": "sk-abc123def456ghij"}))
        matched, msg = self.detector.detect(info)
        assert matched
        assert "inline secret" in msg

    def test_detects_secret_value_pattern(self):
        info = _make_info(_server(env={"MY_VAR": "ghp_abcdefghijklmnopqrstuvwx"}))
        matched, msg = self.detector.detect(info)
        assert matched

    def test_detects_secret_in_headers(self):
        info = _make_info(_server(headers={"Authorization": "Bearer my-token-value123"}))
        matched, msg = self.detector.detect(info)
        assert matched

    def test_ignores_placeholder_env(self):
        info = _make_info(_server(env={"API_KEY": "${API_KEY}"}))
        matched, _ = self.detector.detect(info)
        assert not matched

    def test_ignores_safe_env(self):
        info = _make_info(_server(env={"LOG_LEVEL": "debug"}))
        matched, _ = self.detector.detect(info)
        assert not matched

    def test_no_servers(self):
        matched, _ = self.detector.detect({"servers": []})
        assert not matched


class TestPlaintextHTTPMCP:
    detector = PlaintextHTTPMCP()

    def test_detects_http_url(self):
        info = _make_info(_server(url="http://example.com/mcp"))
        matched, msg = self.detector.detect(info)
        assert matched
        assert "HTTP" in msg

    def test_allows_https_url(self):
        info = _make_info(_server(url="https://example.com/mcp"))
        matched, _ = self.detector.detect(info)
        assert not matched

    def test_no_url(self):
        info = _make_info(_server(command="npx", args=["some-server"]))
        matched, _ = self.detector.detect(info)
        assert not matched


class TestArbitraryShellLauncher:
    detector = ArbitraryShellLauncher()

    @pytest.mark.parametrize("shell", ["bash", "sh", "zsh", "cmd", "powershell", "pwsh"])
    def test_detects_shell_command(self, shell):
        info = _make_info(_server(command=shell, args=["-c", "echo hello"]))
        matched, msg = self.detector.detect(info)
        assert matched
        assert shell in msg.lower() or "shell" in msg.lower()

    def test_detects_shell_flag_in_args(self):
        info = _make_info(_server(command="node", args=["-c", "some-code"]))
        matched, msg = self.detector.detect(info)
        assert matched

    def test_allows_normal_command(self):
        info = _make_info(_server(command="npx", args=["@modelcontextprotocol/server"]))
        matched, _ = self.detector.detect(info)
        assert not matched


class TestSharedProjectMCPConfig:
    detector = SharedProjectMCPConfig()

    @pytest.mark.parametrize(
        "path",
        [
            "/repo/.mcp.json",
            "/repo/.cursor/mcp.json",
            "/repo/.vscode/mcp.json",
            "/repo/.roo/mcp.json",
        ],
    )
    def test_detects_project_scoped_config(self, path):
        info = _make_info(_server(source_path=path))
        matched, msg = self.detector.detect(info)
        assert matched
        assert "project-scoped" in msg

    def test_allows_user_scoped_config(self):
        info = _make_info(
            _server(source_path="/Users/me/Library/Application Support/Claude/config.json")
        )
        matched, _ = self.detector.detect(info)
        assert not matched


class TestFloatingPackageLauncher:
    detector = FloatingPackageLauncher()

    def test_detects_npx_latest(self):
        info = _make_info(_server(command="npx", args=["@modelcontextprotocol/server@latest"]))
        matched, msg = self.detector.detect(info)
        assert matched
        assert "npx" in msg

    def test_detects_npx_dash_y(self):
        info = _make_info(_server(command="npx", args=["-y", "some-package"]))
        matched, msg = self.detector.detect(info)
        assert matched

    def test_detects_uvx(self):
        info = _make_info(_server(command="uvx", args=["some-package"]))
        matched, msg = self.detector.detect(info)
        assert matched
        assert "uvx" in msg

    def test_detects_pipx(self):
        info = _make_info(_server(command="pipx", args=["run", "some-package"]))
        matched, msg = self.detector.detect(info)
        assert matched

    def test_detects_docker_latest(self):
        info = _make_info(_server(command="docker", args=["run", "myimage:latest"]))
        matched, msg = self.detector.detect(info)
        assert matched
        assert "docker" in msg

    def test_allows_pinned_npx(self):
        info = _make_info(_server(command="npx", args=["some-package@1.2.3"]))
        matched, _ = self.detector.detect(info)
        assert not matched


class TestDangerousToolSurface:
    detector = DangerousToolSurface()

    @pytest.mark.parametrize(
        "name",
        ["shell-executor", "exec-server", "run-command", "delete-files", "ssh-tunnel"],
    )
    def test_detects_dangerous_server_name(self, name):
        info = _make_info(_server(server_name=name))
        matched, msg = self.detector.detect(info)
        assert matched
        assert "high-risk" in msg

    def test_detects_dangerous_command(self):
        info = _make_info(_server(server_name="safe-name", command="kubectl"))
        matched, msg = self.detector.detect(info)
        assert matched

    def test_allows_safe_name(self):
        info = _make_info(_server(server_name="weather-api", command="node"))
        matched, _ = self.detector.detect(info)
        assert not matched


class TestOverbroadFilesystemAccess:
    detector = OverbroadFilesystemAccess()

    @pytest.mark.parametrize("path", ["~", ".ssh", ".aws"])
    def test_detects_broad_path_in_args(self, path):
        info = _make_info(_server(args=["--dir", path]))
        matched, msg = self.detector.detect(info)
        assert matched
        assert "broad" in msg or "sensitive" in msg

    @pytest.mark.parametrize("path", ["/", "/root", "/home", "/users"])
    def test_detects_broad_absolute_path(self, path):
        info = _make_info(_server(args=[path]))
        matched, msg = self.detector.detect(info)
        assert matched
        assert "broad" in msg or "sensitive" in msg

    def test_detects_broad_cwd(self):
        info = _make_info(_server(cwd="/"))
        matched, _ = self.detector.detect(info)
        assert matched

    def test_allows_scoped_path(self):
        """A specific project directory should not trigger."""
        info = _make_info(_server(args=["--dir", "/opt/myapp/data"], cwd="/opt/myapp"))
        matched, _ = self.detector.detect(info)
        assert not matched

    def test_allows_safe_path(self):
        info = _make_info(_server(args=["--port", "8080"], cwd=None))
        matched, _ = self.detector.detect(info)
        assert not matched

    def test_no_false_positive_on_substring(self):
        """Paths like /opt/dot.ssh-backup should not trigger the .ssh rule."""
        info = _make_info(_server(args=["/opt/dot.ssh-backup"]))
        matched, _ = self.detector.detect(info)
        assert not matched


class TestMCPMetadataRulesRegistry:
    def test_all_seven_rules_registered(self):
        assert len(MCP_METADATA_RULES) == 7

    def test_rule_names(self):
        expected = {
            "inline-secret-in-mcp-config",
            "plaintext-http-mcp",
            "arbitrary-shell-launcher",
            "shared-project-mcp-config",
            "floating-package-launcher",
            "dangerous-tool-surface",
            "overbroad-filesystem-access",
        }
        assert set(MCP_METADATA_RULES.keys()) == expected
