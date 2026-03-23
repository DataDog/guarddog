from __future__ import annotations

import os
from pathlib import Path

from guarddog.scanners.mcp.models import MCPConfigFile
from guarddog.scanners.mcp.parsers.base import MCPConfigParser


class ContinueParser(MCPConfigParser):
    client_name = "continue"

    def matches(self, path: str) -> bool:
        normalized = path.replace("\\", "/").lower()
        return "/.continue/mcpservers/" in normalized and normalized.endswith((".json", ".yaml", ".yml"))

    def parse(self, path: str) -> MCPConfigFile:
        suffix = Path(path).suffix.lower()
        if suffix == ".json":
            data = self._load_json(path)
        else:
            data = self._load_yaml(path)

        servers = []

        if "mcpServers" in data and isinstance(data["mcpServers"], dict):
            for server_name, server_cfg in data["mcpServers"].items():
                if not isinstance(server_cfg, dict):
                    continue
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
                        scope="project",
                    )
                )
        else:
            server_name = (
                data.get("name")
                or data.get("server")
                or Path(path).stem
            )
            servers.append(
                self._make_server(
                    source_path=os.path.abspath(path),
                    server_name=str(server_name),
                    command=data.get("command"),
                    args=data.get("args"),
                    url=data.get("url"),
                    env=data.get("env"),
                    cwd=data.get("cwd"),
                    headers=data.get("headers"),
                    transport=data.get("transport"),
                    annotations=data.get("annotations"),
                    trust=data.get("trust"),
                    raw=data,
                    scope="project",
                )
            )

        return self._make_config_file(path, servers, scope="project")
