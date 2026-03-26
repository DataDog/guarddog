from __future__ import annotations

import logging
import os
import typing
from dataclasses import dataclass
from typing import List

from guarddog.scanners.mcp.discovery import discover_and_parse_mcp_configs, discover_mcp_configs
from guarddog.scanners.mcp.models import MCPConfigFile, MCPInventory
from guarddog.scanners.mcp_config_scanner import MCPConfigScanner
from guarddog.scanners.scanner import Dependency, DependencyFile, DependencyVersion, ProjectScanner, noop

log = logging.getLogger("guarddog")


@dataclass
class MCPDependencyFile(DependencyFile):
    dependencies: List[Dependency]


class MCPDiscoveryScanner(ProjectScanner):
    """
    Project scanner that discovers MCP configs under a repo/workspace path and
    analyzes each config file locally.
    """

    def __init__(self) -> None:
        super().__init__(MCPConfigScanner())

    def parse_requirements(self, raw_requirements: str) -> List[Dependency]:
        # Not used for MCP because parsing is file-format specific.
        return []

    def find_requirements(self, directory: str) -> list[str]:
        return discover_mcp_configs(directory)

    def _dependency_files_from_inventory(
        self,
        config_files: list[MCPConfigFile],
    ) -> list[DependencyFile]:
        dep_files: list[DependencyFile] = []

        for config_file in config_files:
            dependencies = [
                Dependency(
                    name=server.server_name,
                    versions={DependencyVersion(version=server.transport, location=0)},
                )
                for server in config_file.servers
            ]
            dep_files.append(
                MCPDependencyFile(
                    file_path=config_file.file_path,
                    dependencies=dependencies,
                )
            )

        return dep_files

    def scan_local(
        self,
        path,
        rules=None,
        callback: typing.Callable[[dict], None] = noop,
    ) -> tuple[list[DependencyFile], list[dict]]:
        log.info("Verifying MCP configs under %s", os.path.abspath(path))
        inventory = discover_and_parse_mcp_configs(path)
        dep_files = self._dependency_files_from_inventory(inventory.config_files)

        results: list[dict] = []
        total = len(inventory.config_files)
        for idx, config_file in enumerate(inventory.config_files, 1):
            log.info("[%d/%d] Scanning %s ...", idx, total, config_file.file_path)
            # Build a single-file inventory so the config scanner can reuse
            # the already-parsed data instead of re-discovering and re-parsing.
            single = MCPInventory(config_files=[config_file])
            result = self.package_scanner._scan_inventory(
                config_file.file_path, single, rules=rules,
            )
            shaped = {
                "dependency": config_file.file_path,
                "version": None,
                "result": result,
            }
            callback(shaped)
            results.append(shaped)

        total_issues = sum(r["result"].get("issues", 0) for r in results)
        log.info("Verify complete: scanned %d config file(s), %d total issue(s)", total, total_issues)
        return dep_files, results
