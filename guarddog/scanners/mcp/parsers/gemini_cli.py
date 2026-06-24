from __future__ import annotations

import os

from guarddog.scanners.mcp.models import MCPConfigFile
from guarddog.scanners.mcp.parsers.base import MCPConfigParser


class GeminiCLIParser(MCPConfigParser):
    client_name = "gemini_cli"

    def matches(self, path: str) -> bool:
        normalized = path.replace("\\", "/").lower()
        return normalized.endswith("/.gemini/settings.json")

    def parse(self, path: str) -> MCPConfigFile:
        data = self._load_json(path)
        servers_obj = data.get("mcpServers", data.get("mcp_servers", {}))
        servers = []

        if isinstance(servers_obj, dict):
            for server_name, server_cfg in servers_obj.items():
                if not isinstance(server_cfg, dict):
                    continue
                scope = "project" if "/.gemini/" in path.replace("\\", "/").lower() and not path.startswith(str(os.path.expanduser("~"))) else "user"
                servers.append(
                    self._make_server(
                        source_path=os.path.abspath(path),
                        server_name=str(server_name),
                        command=server_cfg.get("command"),
                        args=server_cfg.get("args"),
                        url=server_cfg.get("url"),
                        env=server_cfg.get("env"),
                        cwd=server_cfg.get("cwd"),
                        headers=server_cfg.get("headers"),
                        transport=server_cfg.get("transport"),
                        annotations=server_cfg.get("annotations"),
                        trust=server_cfg.get("trust"),
                        raw=server_cfg,
                        scope=scope,
                    )
                )

        normalized = os.path.abspath(path).replace("\\", "/").lower()
        home = os.path.expanduser("~").replace("\\", "/").lower()
        scope = "user" if normalized.startswith(home) and normalized.endswith("/.gemini/settings.json") else "project"
        return self._make_config_file(path, servers, scope=scope)
