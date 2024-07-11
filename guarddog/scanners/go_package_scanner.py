import logging
from typing import Tuple
import os
import requests

from guarddog.analyzer.analyzer import Analyzer
from guarddog.ecosystems import ECOSYSTEM
from guarddog.scanners.scanner import PackageScanner

log = logging.getLogger("guarddog")

# See https://go.dev/ref/mod#goproxy-protocol to learn more about the Go modules proxy internals

# TODO: allow users to configure the proxy they wanna use.
GOPROXY_URL = "https://proxy.golang.org"


class GoModuleScanner(PackageScanner):
    def __init__(self) -> None:
        super().__init__(Analyzer(ECOSYSTEM.GO))

    def download_and_get_package_info(
        self, directory: str, package_name: str, version=None
    ) -> Tuple[dict, str]:
        # If the version is not set explicitely, guarddog defaults to the latest
        if not version:
            latest_version_info_url = (
                f"{GOPROXY_URL}/{escape_module_name(package_name)}/@latest"
            )
            log.debug(
                f"Version for Go module {package_name} is unspecified, "
                f"fetching the latest version info from {latest_version_info_url}..."
            )
            latest_version_info = requests.get(latest_version_info_url)
            latest_version_info.raise_for_status()
            latest_version = latest_version_info.json()["Version"]
            log.debug(
                f"Latest version for Go module {package_name} is {latest_version}"
            )
            version = latest_version

        # Most of this logic comes from the NPM package scanner
        zip_url = f"{GOPROXY_URL}/{escape_module_name(package_name)}/@v/{version}.zip"
        zip_path = os.path.join(directory, package_name.replace("/", "-") + ".zip")
        unzipped_path = zip_path.removesuffix(".zip")
        self.download_compressed(zip_url, zip_path, unzipped_path)

        version_info_url = (
            f"{GOPROXY_URL}/{escape_module_name(package_name)}/@v/{version}.info"
        )
        log.debug(
            f"Fetching Go module {package_name}@{version}'s info from {version_info_url}..."
        )
        version_info = requests.get(version_info_url)
        version_info.raise_for_status()

        return version_info.json(), unzipped_path


# As described in https://go.dev/ref/mod#goproxy-protocol:
# > To avoid ambiguity when serving from case-insensitive file systems,
# > the $module and $version elements are case-encoded by replacing every uppercase letter
# > with an exclamation mark followed by the corresponding lower-case letter.
# > This allows modules example.com/M and example.com/m to both be stored on disk,
# > since the former is encoded as example.com/!m.
def escape_module_name(package_name: str) -> str:
    escaped_package_name = ""

    for c in package_name:
        if c.isupper():
            escaped_package_name += f"!{c.lower()}"
        else:
            escaped_package_name += c

    return escaped_package_name
