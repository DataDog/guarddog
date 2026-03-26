from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class MCPServerConfig:
    client: str
    scope: str
    source_path: str
    server_name: str
    transport: str = "unknown"
    command: str | None = None
    args: list[str] = field(default_factory=list)
    url: str | None = None
    env: dict[str, str | None] = field(default_factory=dict)
    cwd: str | None = None
    headers: dict[str, str | None] = field(default_factory=dict)
    annotations: dict[str, Any] = field(default_factory=dict)
    trust: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class MCPConfigFile:
    file_path: str
    client: str
    scope: str
    servers: list[MCPServerConfig] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "client": self.client,
            "scope": self.scope,
            "servers": [server.to_dict() for server in self.servers],
        }


@dataclass
class MCPInventory:
    config_files: list[MCPConfigFile] = field(default_factory=list)

    @property
    def servers(self) -> list[MCPServerConfig]:
        return [
            server
            for config_file in self.config_files
            for server in config_file.servers
        ]

    def to_dict(self) -> dict[str, Any]:
        config_dicts = [config_file.to_dict() for config_file in self.config_files]
        # Reuse the already-serialised server dicts instead of serialising twice.
        all_servers = [
            srv for cf in config_dicts for srv in cf.get("servers", [])
        ]
        return {
            "config_files": config_dicts,
            "servers": all_servers,
        }
