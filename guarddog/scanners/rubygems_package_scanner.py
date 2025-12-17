import logging
import os
from typing import Tuple

import requests
import tarsafe

from guarddog.analyzer.analyzer import Analyzer
from guarddog.ecosystems import ECOSYSTEM
from guarddog.scanners.scanner import PackageScanner

log = logging.getLogger("guarddog")

RUBYGEMS_API_URL = "https://rubygems.org/api/v1"


class RubyGemsPackageScanner(PackageScanner):
    def __init__(self) -> None:
        super().__init__(Analyzer(ECOSYSTEM.RUBYGEMS))

    def download_and_get_package_info(
        self, directory: str, package_name: str, version=None
    ) -> Tuple[dict, str]:
        gem_info = self._get_gem_info(package_name)

        if version is None:
            version = gem_info["version"]

        extract_dir = self._download_gem(package_name, version, directory)
        return gem_info, extract_dir

    def _get_gem_info(self, package_name: str) -> dict:
        url = f"{RUBYGEMS_API_URL}/gems/{package_name}.json"
        log.debug(f"Fetching gem info from {url}")
        response = requests.get(url)
        response.raise_for_status()
        return response.json()

    def _get_gem_version_info(self, package_name: str, version: str) -> dict:
        url = f"{RUBYGEMS_API_URL}/versions/{package_name}.json"
        log.debug(f"Fetching version info from {url}")
        response = requests.get(url)
        response.raise_for_status()

        versions = response.json()
        for v in versions:
            if v["number"] == version:
                return v

        raise Exception(f"Version {version} for gem {package_name} not found")

    def _download_gem(self, package_name: str, version: str, directory: str) -> str:
        gem_url = f"https://rubygems.org/gems/{package_name}-{version}.gem"
        log.debug(f"Downloading gem from {gem_url}")

        response = requests.get(gem_url)
        response.raise_for_status()

        gem_path = os.path.join(directory, f"{package_name}-{version}.gem")
        with open(gem_path, "wb") as f:
            f.write(response.content)

        extract_dir = os.path.join(directory, package_name)
        self._extract_gem(gem_path, extract_dir)

        return extract_dir

    def _extract_gem(self, gem_path: str, extract_dir: str) -> None:
        """
        Extract a .gem file which is a nested tar archive.
        The outer tar contains data.tar.gz which has the actual source.
        """
        os.makedirs(extract_dir, exist_ok=True)

        outer_extract = os.path.join(extract_dir, "_gem_contents")
        os.makedirs(outer_extract, exist_ok=True)

        log.debug(f"Extracting outer gem archive {gem_path}")
        with tarsafe.open(gem_path) as outer_tar:
            outer_tar.extractall(outer_extract)

        data_tar_path = os.path.join(outer_extract, "data.tar.gz")
        if not os.path.exists(data_tar_path):
            data_tar_path = os.path.join(outer_extract, "data.tar")

        if not os.path.exists(data_tar_path):
            raise Exception(f"data.tar.gz not found in gem {gem_path}")

        log.debug(f"Extracting inner data archive {data_tar_path}")
        with tarsafe.open(data_tar_path) as inner_tar:
            inner_tar.extractall(extract_dir)
