from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from guarddog.scanners.mcp.models import MCPConfigFile, MCPServerConfig

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None


class MCPConfigParser(ABC):
    client_name = "unknown"

    @abstractmethod
    def matches(self, path: str) -> bool:
        raise NotImplementedError

    @abstractmethod
    def parse(self, path: str) -> MCPConfigFile:
        raise NotImplementedError

    def _read_text(self, path: str) -> str:
        return Path(path).read_text(encoding="utf-8")

    def _load_json(self, path: str) -> dict[str, Any]:
        data = json.loads(self._read_text(path))
        if not isinstance(data, dict):
            raise ValueError(f"Expected JSON object in {path}")
        return data

    def _load_toml(self, path: str) -> dict[str, Any]:
        with open(path, "rb") as f:
            data = __import__("tomllib").load(f)
        if not isinstance(data, dict):
            raise ValueError(f"Expected TOML object in {path}")
        return data

    def _load_yaml(self, path: str) -> dict[str, Any]:
        if yaml is None:
            raise RuntimeError(
                "PyYAML is required to parse YAML MCP configs but is not installed"
            )
        data = yaml.safe_load(self._read_text(path)) or {}
        if not isinstance(data, dict):
            raise ValueError(f"Expected YAML object in {path}")
        return data

    def _normalize_env(self, value: Any) -> dict[str, str | None]:
        if not isinstance(value, dict):
            return {}

        result: dict[str, str | None] = {}
        for key, env_value in value.items():
            if env_value is None:
                result[str(key)] = None
            elif isinstance(env_value, (str, int, float, bool)):
                result[str(key)] = str(env_value)
            else:
                result[str(key)] = json.dumps(env_value, sort_keys=True)
        return result

    def _normalize_headers(self, value: Any) -> dict[str, str | None]:
        return self._normalize_env(value)

    def _normalize_args(self, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(v) for v in value]
        if isinstance(value, str):
            return [value]
        return [str(value)]

    def _infer_transport(
        self,
        *,
        command: str | None = None,
        url: str | None = None,
        transport: str | None = None,
    ) -> str:
        if transport:
            normalized = str(transport).strip().lower()
            if normalized in {"stdio", "http", "https", "sse", "streamable-http"}:
                return "http" if normalized == "https" else normalized
            return normalized

        if url:
            lower_url = url.lower()
            if lower_url.startswith(("http://", "https://")):
                return "http"
            if lower_url.startswith("sse://"):
                return "sse"

        if command:
            return "stdio"

        return "unknown"

    def _scope_from_path(self, path: str) -> str:
        normalized = path.replace("\\", "/").lower()
        project_markers = [
            "/.vscode/",
            "/.cursor/",
            "/.continue/",
            "/.roo/",
            "/.gemini/",
            "/.mcp.json",
        ]
        if any(marker in normalized for marker in project_markers):
            return "project"
        home = str(Path.home()).replace("\\", "/").lower()
        if normalized.startswith(home):
            return "user"
        return "unknown"

    def _make_server(
        self,
        *,
        source_path: str,
        server_name: str,
        command: str | None = None,
        args: Any = None,
        url: str | None = None,
        env: Any = None,
        cwd: str | None = None,
        headers: Any = None,
        transport: str | None = None,
        annotations: dict[str, Any] | None = None,
        trust: dict[str, Any] | None = None,
        raw: dict[str, Any] | None = None,
        scope: str | None = None,
    ) -> MCPServerConfig:
        normalized_scope = scope or self._scope_from_path(source_path)
        return MCPServerConfig(
            client=self.client_name,
            scope=normalized_scope,
            source_path=source_path,
            server_name=server_name,
            transport=self._infer_transport(
                command=command,
                url=url,
                transport=transport,
            ),
            command=command,
            args=self._normalize_args(args),
            url=url,
            env=self._normalize_env(env),
            cwd=cwd,
            headers=self._normalize_headers(headers),
            annotations=annotations or {},
            trust=trust or {},
            raw=raw or {},
        )

    def _make_config_file(
        self,
        path: str,
        servers: list[MCPServerConfig],
        scope: str | None = None,
    ) -> MCPConfigFile:
        return MCPConfigFile(
            file_path=os.path.abspath(path),
            client=self.client_name,
            scope=scope or self._scope_from_path(path),
            servers=servers,
        )
