import json
import logging
import os
import typing

import requests

from guarddog.analyzer.analyzer import Analyzer
from guarddog.ecosystems import ECOSYSTEM
from guarddog.scanners.scanner import PackageScanner, noop

log = logging.getLogger("guarddog")

MARKETPLACE_URL = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery"
MARKETPLACE_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json;api-version=3.0-preview.1"
}
MARKETPLACE_DOWNLOAD_LINK_ASSET_TYPE = "Microsoft.VisualStudio.Services.VSIXPackage"
VSIX_FILE_EXTENSION = ".vsix"


class ExtensionScanner(PackageScanner):
    def __init__(self) -> None:
        super().__init__(Analyzer(ECOSYSTEM.EXTENSION))

    def download_and_get_package_info(self,
                                      directory: str,
                                      package_name: str,
                                      version=None) -> typing.Tuple[dict,
                                                                    str]:
        """
        Downloads a VSCode extension from the marketplace and extracts it

        Args:
            directory: Directory to download to
            package_name: Extension identifier (publisher.extension format)
            version: Specific version or default to latest

        Returns:
            Tuple of (extension metadata(manifest and marketplace) info, extracted_path)
        """
        marketplace_metadata, vsix_url = self._get_marketplace_info_and_url(package_name, version)

        vsix_path = os.path.join(directory, package_name.replace("/", "-") + VSIX_FILE_EXTENSION)
        extracted_path = vsix_path.removesuffix(VSIX_FILE_EXTENSION)

        log.debug(f"Downloading VSCode extension from {vsix_url}")

        self.download_compressed(vsix_url, vsix_path, extracted_path)

        manifest_metadata = self._extract_manifest_metadata(extracted_path)

        combined_metadata = {
            "marketplace": marketplace_metadata,
            "manifest": manifest_metadata,
            "source": "remote"
        }

        return combined_metadata, extracted_path

    def _get_marketplace_info_and_url(
            self,
            package_name: str,
            version: typing.Optional[str] = None) -> typing.Tuple[dict, str]:
        """Get marketplace metadata and VSIX download URL"""
        payload = {
            "filters": [
                {
                    "criteria": [
                        {
                            "filterType": 7,
                            "value": package_name
                        }
                    ]
                }
            ],
            "flags": 958
        }

        response = requests.post(
            MARKETPLACE_URL,
            headers=MARKETPLACE_HEADERS,
            json=payload)

        response.raise_for_status()

        data = response.json()

        if not data.get("results") or not data["results"][0].get("extensions"):
            raise ValueError(
                f"Extension {package_name} not found in marketplace")

        extension_info = data["results"][0]["extensions"][0]
        versions = extension_info.get("versions", [])

        if not versions:
            raise ValueError(
                f"No versions available for this extension: {package_name}")

        target_version = None
        if version is None:
            # if not version is provided, default to latest
            target_version = versions[0]
        else:
            for v in versions:
                if v.get("version") == version:
                    target_version = v
                    break
            if target_version is None:
                raise ValueError(
                    f"Version {version} not found for extension: {package_name}")

        # Extract download URL
        files = target_version.get("files", [])
        vsix_url = None
        for file_info in files:
            if file_info.get("assetType") == MARKETPLACE_DOWNLOAD_LINK_ASSET_TYPE:
                vsix_url = file_info.get("source")
                break

        if not vsix_url:
            raise ValueError(
                f"No VSIX download link available for this extension: {package_name}")

        # Extract statistics from the statistics array
        stats = {stat["statisticName"]: stat["value"]
                 for stat in extension_info.get("statistics", [])}
        # ... and the marketplace metadata
        # TODO: it might be interesting to add heuristics regarding the rating
        # cound and the weghtedRating (see the ranking algo hack)
        marketplace_metadata = {
            "extensionName": extension_info.get("extensionName", ""),
            "flags": extension_info.get("flags", []),
            "download_count": int(stats.get("downloadCount", 0)),
            "publisher": extension_info.get("publisher", {}),
            "publisher_flags": extension_info.get("publisher_flags", ""),
            "publisher_domain": extension_info.get("domain", ""),
            "publisher_isDomainVerified": extension_info.get("publisher_isDomainVerified", False), }

        return marketplace_metadata, vsix_url

    def _extract_manifest_metadata(self, extracted_path: str) -> dict:
        """Extract metadata from the extension's package.json manifest"""

        log.debug(f"Starting manifest extraction from: {extracted_path}")

        package_json_path = None
        for root, dirs, files in os.walk(extracted_path):
            if "package.json" in files:
                package_json_path = os.path.join(root, "package.json")
                break

        if package_json_path is None:
            log.warning(f"No package.json found in {extracted_path}")
            return {}

        log.debug(f"Found package.json at: {package_json_path}")
        try:
            with open(package_json_path, 'r', encoding='utf-8') as f:
                manifest_data = json.load(f)
            log.debug(
                f"Successfully parsed package.json with {len(manifest_data)} keys")
        except Exception as e:
            log.warning(
                f"Failed to read manifest from {package_json_path}: {e}")
            return {}

        registered_commands = manifest_data.get("contributes", {}).get("commands", [])
        extracted_metadata = {
            "name": manifest_data.get("name", ""),
            "displayName": manifest_data.get("displayName", ""),
            "description": manifest_data.get("description", ""),
            "version": manifest_data.get("version", ""),
            "publisher": manifest_data.get("publisher", ""),
            "repository": manifest_data.get("repository", {}),
            "activationEvents": manifest_data.get("activationEvents", []),
            "categories": manifest_data.get("categories", []),
            "registeredCommands": registered_commands,
        }

        log.debug(f"Extracted manifest metadata: {extracted_metadata}")
        return extracted_metadata

    def scan_local(self, path: str, rules=None, callback: typing.Callable[[dict], None] = noop) -> dict:
        """
        Scan a local VSCode extension directory

        Args:
            path: Path to extension directory containing package.json
            rules: Set of rules to use
            callback: Callback to apply to analyzer output

        Returns:
            Scan results
        """
        # Extract manifest metadata from the extension directory
        manifest_metadata = self._extract_manifest_metadata(path)

        # For local directory scanning, only use manifest metadata
        package_info = {
            "marketplace": {},  # Empty for local scans
            "manifest": manifest_metadata,
            "source": "local"
        }

        if rules is not None:
            rules = set(rules)

        # Use full analyze method to include both metadata and sourcecode analysis
        results = self.analyzer.analyze(path, package_info, rules)
        callback(results)

        return results
