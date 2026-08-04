import logging
import os
from typing import Tuple
from urllib.parse import quote, urljoin

import requests

from guarddog.analyzer.analyzer import Analyzer
from guarddog.ecosystems import ECOSYSTEM
from guarddog.scanners.scanner import PackageScanner

log = logging.getLogger("guarddog")

CRATES_IO_API_URL = "https://crates.io/api/v1"
CRATES_IO_URL = "https://crates.io"


class CratesPackageScanner(PackageScanner):
    def __init__(self) -> None:
        super().__init__(Analyzer(ECOSYSTEM.CRATES))
        self.request_headers = {
            "User-Agent": "guarddog (https://github.com/DataDog/guarddog)"
        }

    def download_and_get_package_info(
        self, directory: str, package_name: str, version=None
    ) -> Tuple[dict, str]:
        package_info = self._get_crate_info(package_name)
        resolved_version = self.get_package_version(package_info, version)
        release = next(
            (
                release
                for release in package_info.get("versions", [])
                if release.get("num") == resolved_version
            ),
            None,
        )
        if release is None:
            raise ValueError(
                f"Version {resolved_version} for crate {package_name} not found"
            )

        download_path = release.get("dl_path")
        if not download_path:
            raise ValueError(
                f"Download path for crate {package_name} {resolved_version} not found"
            )

        path_name = quote(package_name, safe="")
        path_version = quote(str(resolved_version), safe="")
        path_stem = f"{path_name}-{path_version}"
        archive_path = os.path.join(directory, f"{path_stem}.crate")
        extract_path = os.path.join(directory, path_stem)
        download_url = urljoin(CRATES_IO_URL, download_path)
        self.download_compressed(download_url, archive_path, extract_path)

        return package_info, extract_path

    def get_package_version(self, package_info: dict, requested_version=None):
        if requested_version is not None:
            return requested_version

        crate_info = package_info.get("crate", {})
        version = crate_info.get("max_stable_version") or crate_info.get("max_version")
        if version is None:
            raise ValueError("Unable to determine the latest crate version")
        return version

    def _get_crate_info(self, package_name: str) -> dict:
        encoded_name = quote(package_name, safe="")
        url = f"{CRATES_IO_API_URL}/crates/{encoded_name}"
        log.debug(f"Fetching crate info from {url}")
        response = requests.get(url, headers=self.request_headers)
        response.raise_for_status()
        package_info = response.json()
        if "crate" not in package_info:
            raise ValueError(f"Error retrieving crate: {package_name}")
        return package_info

    def _fetch_archive(self, url: str, archive_path: str) -> None:
        log.debug(f"Downloading crate archive from {url}")
        response = requests.get(url, headers=self.request_headers, stream=True)
        response.raise_for_status()
        with open(archive_path, "wb") as archive:
            archive.write(response.raw.read())
