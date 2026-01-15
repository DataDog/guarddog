import logging
import os
from typing import Tuple

import requests

from guarddog.analyzer.analyzer import Analyzer
from guarddog.ecosystems import ECOSYSTEM
from guarddog.scanners.scanner import PackageScanner
from guarddog.utils.archives import safe_extract

log = logging.getLogger("guarddog")

RUBYGEMS_API_URL = "https://rubygems.org/api/v1"


class RubyGemsPackageScanner(PackageScanner):
    def __init__(self) -> None:
        super().__init__(Analyzer(ECOSYSTEM.RUBYGEMS))

    def _extract_archive(self, archive_path: str, target_path: str) -> None:
        """
        Override to handle .gem files which are nested tar archives.
        The outer tar contains data.tar.gz which has the actual source code.

        Args:
            archive_path (str): path to the .gem file
            target_path (str): directory to extract the source code into
        """
        if not archive_path.endswith(".gem"):
            # Fall back to default behavior for non-gem archives
            super()._extract_archive(archive_path, target_path)
            return

        os.makedirs(target_path, exist_ok=True)

        # Extract outer .gem archive to a temporary location
        outer_extract = os.path.join(target_path, "_gem_contents")
        os.makedirs(outer_extract, exist_ok=True)

        log.debug(f"Extracting outer gem archive {archive_path}")
        safe_extract(archive_path, outer_extract)

        # Find the inner data archive (data.tar.gz or data.tar)
        data_tar_path = os.path.join(outer_extract, "data.tar.gz")
        if not os.path.exists(data_tar_path):
            data_tar_path = os.path.join(outer_extract, "data.tar")

        if not os.path.exists(data_tar_path):
            raise Exception(f"data.tar.gz not found in gem {archive_path}")

        # Extract the inner data archive to the final target
        log.debug(f"Extracting inner data archive {data_tar_path}")
        safe_extract(data_tar_path, target_path)

        log.debug(f"Successfully extracted gem files to {target_path}")

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
        """
        Downloads and extracts a RubyGem package.

        Uses the parent class's download_compressed method which will call our
        overridden _extract_archive method to handle the nested .gem format.

        Args:
            package_name (str): name of the gem
            version (str): version of the gem
            directory (str): directory to download and extract to

        Returns:
            str: path to the extracted gem contents
        """
        gem_url = f"https://rubygems.org/gems/{package_name}-{version}.gem"
        gem_path = os.path.join(directory, f"{package_name}-{version}.gem")
        extract_dir = os.path.join(directory, package_name)

        # Use parent class method which handles download and extraction
        # The extraction will use our overridden _extract_archive method
        self.download_compressed(gem_url, gem_path, extract_dir)

        return extract_dir
