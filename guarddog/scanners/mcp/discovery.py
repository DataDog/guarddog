from __future__ import annotations

import logging
import os
from pathlib import Path

from guarddog.scanners.mcp.models import MCPConfigFile, MCPInventory
from guarddog.scanners.mcp.parsers import (
    ClaudeCodeParser,
    ClaudeDesktopParser,
    ClineParser,
    CodexParser,
    ContinueParser,
    CopilotCLIParser,
    CursorParser,
    GeminiCLIParser,
    RooCodeParser,
    VSCodeParser,
    WindsurfParser,
)

log = logging.getLogger("guarddog")


PARSERS = [
    ClaudeDesktopParser(),
    ClaudeCodeParser(),
    CursorParser(),
    VSCodeParser(),
    WindsurfParser(),
    ClineParser(),
    RooCodeParser(),
    ContinueParser(),
    CodexParser(),
    GeminiCLIParser(),
    CopilotCLIParser(),
]


def _candidate_paths(root: str) -> list[str]:
    root_path = Path(root)
    candidates: set[str] = set()

    if root_path.is_file():
        return [str(root_path.resolve())]

    # Project/workspace candidates
    project_patterns = [
        ".mcp.json",
        ".claude.json",
        ".cursor/mcp.json",
        ".vscode/mcp.json",
        ".roo/mcp.json",
        ".gemini/settings.json",
        ".continue/mcpServers/*.json",
        ".continue/mcpServers/*.yaml",
        ".continue/mcpServers/*.yml",
    ]
    for pattern in project_patterns:
        candidates.update(str(p.resolve()) for p in root_path.glob(pattern))

    # User config candidates only when scanning home-ish paths
    home = Path.home()
    resolved_root = str(root_path.resolve())
    resolved_home = str(home.resolve())
    scan_user_space = (
        resolved_root == resolved_home
        or resolved_root.startswith(resolved_home + os.sep)
    )
    if scan_user_space:
        user_candidates = [
            home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
            home / ".claude.json",
            home / ".cursor" / "mcp.json",
            home / ".codeium" / "windsurf" / "mcp_config.json",
            home / ".codex" / "config.toml",
            home / ".gemini" / "settings.json",
            home / ".copilot" / "mcp-config.json",
        ]
        for candidate in user_candidates:
            if candidate.exists():
                candidates.add(str(candidate.resolve()))

        # Cline / Roo Code / Windsurf settings in known VS Code-style dirs.
        # Avoid expensive ** globs over all of $HOME; instead target the
        # well-known extension-host directories where globalStorage lives.
        _vscode_dirs = [
            home / ".vscode" / "extensions",
            home / ".vscode-server" / "extensions",
            home / ".cursor" / "extensions",
        ]
        _config_dirs = [
            home / ".config",
            home / "AppData" / "Roaming",
        ]
        for d in _config_dirs:
            if d.is_dir():
                for p in d.glob("**/cline_mcp_settings.json"):
                    if p.is_file():
                        candidates.add(str(p.resolve()))
                for p in d.glob("**/mcp_settings.json"):
                    if p.is_file():
                        candidates.add(str(p.resolve()))
        for d in _vscode_dirs:
            if d.is_dir():
                for p in d.glob("**/globalStorage/**/cline_mcp_settings.json"):
                    if p.is_file():
                        candidates.add(str(p.resolve()))
                for p in d.glob("**/globalStorage/**/mcp_settings.json"):
                    if p.is_file():
                        candidates.add(str(p.resolve()))

    return sorted(candidates)


def parse_mcp_config_file(path: str) -> MCPConfigFile | None:
    for parser in PARSERS:
        if parser.matches(path):
            try:
                return parser.parse(path)
            except Exception as exc:
                log.debug("Failed to parse %s with %s: %s", path, parser.client_name, exc)
                return None
    return None


def discover_mcp_configs(path: str) -> list[str]:
    candidates = _candidate_paths(path)
    log.info("Discovering MCP configs under %s ...", path)
    log.info("Found %d candidate config file(s)", len(candidates))
    for c in candidates:
        log.debug("  candidate: %s", c)
    return candidates


def discover_and_parse_mcp_configs(path: str) -> MCPInventory:
    config_files: list[MCPConfigFile] = []

    for candidate in discover_mcp_configs(path):
        parsed = parse_mcp_config_file(candidate)
        if parsed is not None:
            server_count = len(parsed.servers)
            log.info(
                "Parsed %s (%s, %d server(s))",
                candidate, parsed.client, server_count,
            )
            config_files.append(parsed)
        else:
            log.debug("Skipped %s (no matching parser or parse error)", candidate)

    total_servers = sum(len(cf.servers) for cf in config_files)
    log.info(
        "Discovery complete: %d config file(s), %d server(s) total",
        len(config_files), total_servers,
    )
    return MCPInventory(config_files=config_files)
