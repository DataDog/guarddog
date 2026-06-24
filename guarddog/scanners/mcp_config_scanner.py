from __future__ import annotations

import logging
import os
import typing

from guarddog.analyzer.analyzer import Analyzer
from guarddog.ecosystems import ECOSYSTEM
from guarddog.scanners.mcp.discovery import discover_and_parse_mcp_configs
from guarddog.scanners.scanner import PackageScanner, noop

log = logging.getLogger("guarddog")


class MCPConfigScanner(PackageScanner):
    """
    Local-only scanner for MCP config files/directories.
    """

    def __init__(self) -> None:
        super().__init__(Analyzer(ECOSYSTEM.MCP))

    def scan_local(
        self,
        path,
        rules=None,
        callback: typing.Callable[[dict], None] = noop,
    ) -> dict:
        log.info("Scanning MCP configs at %s", os.path.abspath(path))
        inventory = discover_and_parse_mcp_configs(path)
        return self._scan_inventory(path, inventory, rules, callback)

    def _scan_inventory(
        self,
        path,
        inventory,
        rules=None,
        callback: typing.Callable[[dict], None] = noop,
    ) -> dict:
        """Run metadata analysis on a pre-parsed MCPInventory (avoids re-discovery)."""
        if rules is not None:
            rules = set(rules)

        payload = inventory.to_dict()

        num_rules = len(rules) if rules else len(self.analyzer.metadata_ruleset)
        log.info("Running %d metadata rule(s) against %d server(s) ...",
                 num_rules, len(inventory.servers))

        result = self.analyzer.analyze_metadata(
            path=os.path.abspath(path),
            info=payload,
            rules=rules,
            name=os.path.basename(path),
            version=None,
        )

        log.info("Scan complete: %d issue(s) found", result.get("issues", 0))

        result["path"] = os.path.abspath(path)
        result["inventory"] = payload
        callback(result)
        return result

    def download_and_get_package_info(
        self,
        directory: str,
        package_name: str,
        version=None,
    ) -> tuple[dict, str]:
        raise NotImplementedError("Remote MCP scans are not supported")
