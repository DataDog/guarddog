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

# VSCode Marketplace API filter types
# FilterType 7 = publisherName.extensionName (search by exact extension identifier)
MARKETPLACE_FILTER_TYPE_EXTENSION_NAME = 7

# VSCode Marketplace API flags (bitwise combination)
# 446 = IncludeVersions | IncludeFiles | IncludeMetadata
MARKETPLACE_FLAGS_FULL_METADATA = 446


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
            Tuple of (marketplace API response, extracted_path)
        """
        marketplace_data, vsix_url = self._get_marketplace_info_and_url(package_name, version)

        vsix_path = os.path.join(directory, package_name.replace("/", "-") + VSIX_FILE_EXTENSION)
        extracted_path = vsix_path.removesuffix(VSIX_FILE_EXTENSION)

        log.debug(f"Downloading VSCode extension from {vsix_url}")

        self.download_compressed(vsix_url, vsix_path, extracted_path)

        return marketplace_data, extracted_path

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
                            "filterType": MARKETPLACE_FILTER_TYPE_EXTENSION_NAME,
                            "value": package_name
                        }
                    ]
                }
            ],
            "flags": MARKETPLACE_FLAGS_FULL_METADATA
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

        return data, vsix_url

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
        if rules is not None:
            rules = set(rules)

        # Use only sourcecode analysis for local scans, consistent with other ecosystems
        results = self.analyzer.analyze_sourcecode(path, rules=rules)
        callback(results)

        return results
