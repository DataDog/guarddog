from __future__ import annotations

import re
from typing import Any, Iterable

from guarddog.analyzer.metadata.detector import Detector

_GUARDDOG_DOCS_BASE = "https://github.com/DataDog/guarddog/wiki/MCP-Rules"

SECRET_KEY_RE = re.compile(
    r"(api[_-]?key|token|secret|password|passwd|authorization|auth|cookie|session)",
    re.IGNORECASE,
)

SECRET_VALUE_RE = re.compile(
    r"(?i)(sk-[a-z0-9]{16,}|ghp_[a-z0-9]{20,}|github_pat_[a-z0-9_]{20,}|bearer\s+[a-z0-9._-]{10,})"
)

DANGEROUS_NAME_RE = re.compile(
    r"(shell|exec|run|delete|write|push|deploy|ssh|kubectl|terraform|sql|browser)",
    re.IGNORECASE,
)


def _servers(package_info: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(package_info, dict):
        return []
    servers = package_info.get("servers", [])
    return [server for server in servers if isinstance(server, dict)]


def _is_placeholder(value: str | None) -> bool:
    if value is None:
        return False
    return (
        "${" in value
        or value.startswith("$")
        or value.startswith("%")
        or (value.startswith("{") and value.endswith("}"))
    )


def _iter_secret_candidates(server: dict[str, Any]) -> Iterable[tuple[str, str]]:
    env = server.get("env", {})
    headers = server.get("headers", {})
    for section_name, section in (("env", env), ("headers", headers)):
        if not isinstance(section, dict):
            continue
        for key, value in section.items():
            if value is None:
                continue
            value_str = str(value)
            if _is_placeholder(value_str):
                continue
            yield f"{section_name}.{key}", value_str


class InlineSecretInMCPConfig(Detector):
    RULE_NAME = "inline-secret-in-mcp-config"

    def __init__(self) -> None:
        super().__init__(
            self.RULE_NAME,
            "Detects inline secrets in MCP config env vars or headers",
            help_url=f"{_GUARDDOG_DOCS_BASE}#inline-secret-in-mcp-config",
            verbose_description=(
                "Hard-coded credentials in MCP configuration files are exposed to "
                "anyone with read access to the config. Secrets in env vars or headers "
                "should be referenced via environment variable expansion (e.g. "
                "${API_KEY}) or a secrets manager rather than stored as plaintext values. "
                "Leaked API keys and tokens can lead to unauthorized access to external "
                "services."
            ),
        )

    def detect(self, package_info, path=None, name=None, version=None):
        for server in _servers(package_info):
            server_name = server.get("server_name", "<unknown>")
            for field_name, value in _iter_secret_candidates(server):
                if SECRET_KEY_RE.search(field_name) or SECRET_VALUE_RE.search(value):
                    return (
                        True,
                        f"MCP server '{server_name}' contains an inline secret in '{field_name}'",
                    )
        return (False, None)


class PlaintextHTTPMCP(Detector):
    RULE_NAME = "plaintext-http-mcp"

    def __init__(self) -> None:
        super().__init__(
            self.RULE_NAME,
            "Detects MCP servers using plaintext HTTP",
            help_url=f"{_GUARDDOG_DOCS_BASE}#plaintext-http-mcp",
            verbose_description=(
                "MCP servers configured with http:// endpoints transmit tool calls, "
                "responses, and any embedded credentials in cleartext. A network-level "
                "attacker can intercept or modify traffic. Use https:// to ensure TLS "
                "encryption for all MCP transport."
            ),
        )

    def detect(self, package_info, path=None, name=None, version=None):
        for server in _servers(package_info):
            url = server.get("url")
            if isinstance(url, str) and url.lower().startswith("http://"):
                return (
                    True,
                    f"MCP server '{server.get('server_name', '<unknown>')}' uses insecure HTTP endpoint '{url}'",
                )
        return (False, None)


class ArbitraryShellLauncher(Detector):
    RULE_NAME = "arbitrary-shell-launcher"

    _SHELL_COMMANDS = {
        "bash", "sh", "zsh", "cmd", "powershell", "pwsh",
        "fish", "ksh", "csh", "tcsh", "dash",
    }

    def __init__(self) -> None:
        super().__init__(
            self.RULE_NAME,
            "Detects MCP servers launched through a shell wrapper",
            help_url=f"{_GUARDDOG_DOCS_BASE}#arbitrary-shell-launcher",
            verbose_description=(
                "Launching an MCP server through a shell interpreter (e.g. bash -c '...') "
                "allows arbitrary command execution and makes it difficult to audit what "
                "actually runs. The shell may expand variables, follow pipes, or execute "
                "additional commands. Prefer invoking the server binary directly with "
                "explicit arguments."
            ),
        )

    def detect(self, package_info, path=None, name=None, version=None):
        for server in _servers(package_info):
            command = str(server.get("command") or "").lower()
            args = [str(arg).lower() for arg in server.get("args", [])]

            if command in self._SHELL_COMMANDS:
                return (
                    True,
                    f"MCP server '{server.get('server_name', '<unknown>')}' is launched via shell command '{command}'",
                )

            dangerous_flags = {"-c", "/c", "-command", "-encodedcommand"}
            if any(arg in dangerous_flags for arg in args):
                return (
                    True,
                    f"MCP server '{server.get('server_name', '<unknown>')}' uses shell execution flags in args",
                )

        return (False, None)


class SharedProjectMCPConfig(Detector):
    RULE_NAME = "shared-project-mcp-config"

    def __init__(self) -> None:
        super().__init__(
            self.RULE_NAME,
            "Detects project-scoped MCP configuration likely to be shared in a repository",
            help_url=f"{_GUARDDOG_DOCS_BASE}#shared-project-mcp-config",
            verbose_description=(
                "Project-scoped MCP config files (e.g. .mcp.json, .cursor/mcp.json) "
                "are typically committed to version control and shared with all "
                "collaborators and CI. A malicious contributor could add or modify server "
                "entries to exfiltrate data or run arbitrary code on other developers' "
                "machines. Review project MCP configs carefully during code review and "
                "consider whether they should be in .gitignore."
            ),
        )

    def detect(self, package_info, path=None, name=None, version=None):
        for server in _servers(package_info):
            source_path = str(server.get("source_path") or "")
            normalized = source_path.replace("\\", "/").lower()
            if any(
                normalized.endswith(marker)
                for marker in (
                    "/.mcp.json",
                    "/.claude.json",
                    "/.cursor/mcp.json",
                    "/.vscode/mcp.json",
                    "/.roo/mcp.json",
                )
            ):
                return (
                    True,
                    f"MCP config '{source_path}' is project-scoped and may be shared with collaborators or CI",
                )
        return (False, None)


class FloatingPackageLauncher(Detector):
    RULE_NAME = "floating-package-launcher"

    _VERSION_PIN_RE = re.compile(r"@[\d]")

    def __init__(self) -> None:
        super().__init__(
            self.RULE_NAME,
            "Detects unpinned launchers such as npx, uvx, pipx, or docker latest",
            help_url=f"{_GUARDDOG_DOCS_BASE}#floating-package-launcher",
            verbose_description=(
                "Package launchers like npx, uvx, and pipx resolve packages at runtime. "
                "Without an explicit version pin, the resolved package can change between "
                "runs. An attacker who compromises a package or publishes a typosquat can "
                "execute arbitrary code the next time the MCP server starts. Pin all "
                "packages to a specific version (e.g. npx some-package@1.2.3)."
            ),
        )

    def detect(self, package_info, path=None, name=None, version=None):
        for server in _servers(package_info):
            command = str(server.get("command") or "").lower()
            args = [str(arg) for arg in server.get("args", [])]
            args_lower = [a.lower() for a in args]
            rendered = " ".join([command, *args_lower]).strip()

            if command == "npx" and ("@latest" in rendered or "-y" in args_lower):
                return (
                    True,
                    f"MCP server '{server.get('server_name', '<unknown>')}' is launched with floating npx package resolution",
                )

            if command in {"uvx", "pipx"}:
                if not any(self._VERSION_PIN_RE.search(a) for a in args):
                    return (
                        True,
                        f"MCP server '{server.get('server_name', '<unknown>')}' is launched through '{command}' without an explicit pinned package version",
                    )

            if command == "docker" and any(":latest" in arg for arg in args_lower):
                return (
                    True,
                    f"MCP server '{server.get('server_name', '<unknown>')}' uses a docker image pinned to ':latest'",
                )

        return (False, None)


class DangerousToolSurface(Detector):
    RULE_NAME = "dangerous-tool-surface"

    def __init__(self) -> None:
        super().__init__(
            self.RULE_NAME,
            "Detects MCP server names suggesting exec, write, admin, or automation capabilities",
            help_url=f"{_GUARDDOG_DOCS_BASE}#dangerous-tool-surface",
            verbose_description=(
                "MCP servers whose name or command suggests destructive or privileged "
                "operations (shell, exec, delete, deploy, ssh, kubectl, etc.) present a "
                "higher risk surface. If an AI agent is granted access to such a server, "
                "a prompt-injection or misconfiguration could lead to unintended system "
                "changes. Verify that the server is necessary and scope its permissions "
                "to the minimum required."
            ),
        )

    def detect(self, package_info, path=None, name=None, version=None):
        for server in _servers(package_info):
            server_name = str(server.get("server_name") or "")
            command = str(server.get("command") or "")
            if DANGEROUS_NAME_RE.search(server_name) or DANGEROUS_NAME_RE.search(command):
                return (
                    True,
                    f"MCP server '{server_name}' exposes a potentially high-risk tool surface",
                )

        return (False, None)


class OverbroadFilesystemAccess(Detector):
    RULE_NAME = "overbroad-filesystem-access"

    _HIGH_RISK_PATTERNS = [
        re.compile(r"(?:^|\s)/$|(?:^|\s)/\s"),                          # bare root /
        re.compile(r"(?:^|\s)~(?:\s|/|$)"),                             # bare tilde
        re.compile(r"(?:^|[\s/])\.ssh(?:\s|/|$)"),                      # .ssh dir
        re.compile(r"(?:^|[\s/])\.aws(?:\s|/|$)"),                      # .aws dir
        re.compile(r"(?:^|[\s/])\.config/gcloud(?:\s|/|$)"),            # gcloud config
        re.compile(r"(?:^|\s)/root(?:\s|/|$)"),                         # /root
        re.compile(r"(?:^|\s)/home(?:\s|/|$)", re.IGNORECASE),          # /home
        re.compile(r"(?:^|\s)/users(?:\s|/|$)", re.IGNORECASE),         # /users
    ]

    def __init__(self) -> None:
        super().__init__(
            self.RULE_NAME,
            "Detects MCP servers configured with broad filesystem scope",
            help_url=f"{_GUARDDOG_DOCS_BASE}#overbroad-filesystem-access",
            verbose_description=(
                "MCP servers that receive access to broad or sensitive filesystem paths "
                "(/, ~, /home, .ssh, .aws) can read credentials, private keys, or modify "
                "system files if the server is compromised or the AI agent is manipulated. "
                "Scope filesystem arguments to the narrowest directory required for the "
                "task (e.g. the current project directory)."
            ),
        )

    def detect(self, package_info, path=None, name=None, version=None):
        for server in _servers(package_info):
            args = [str(arg) for arg in server.get("args", [])]
            cwd = str(server.get("cwd") or "")
            haystack = " ".join(args + [cwd])

            for pattern in self._HIGH_RISK_PATTERNS:
                if pattern.search(haystack):
                    return (
                        True,
                        f"MCP server '{server.get('server_name', '<unknown>')}' appears to target a broad or sensitive filesystem scope",
                    )

        return (False, None)


MCP_METADATA_RULES = {
    InlineSecretInMCPConfig.RULE_NAME: InlineSecretInMCPConfig(),
    PlaintextHTTPMCP.RULE_NAME: PlaintextHTTPMCP(),
    ArbitraryShellLauncher.RULE_NAME: ArbitraryShellLauncher(),
    SharedProjectMCPConfig.RULE_NAME: SharedProjectMCPConfig(),
    FloatingPackageLauncher.RULE_NAME: FloatingPackageLauncher(),
    DangerousToolSurface.RULE_NAME: DangerousToolSurface(),
    OverbroadFilesystemAccess.RULE_NAME: OverbroadFilesystemAccess(),
}
