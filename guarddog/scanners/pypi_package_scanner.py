import os
import typing
from urllib.parse import quote, urlparse

from guarddog.analyzer.analyzer import Analyzer
from guarddog.ecosystems import ECOSYSTEM
from guarddog.scanners.scanner import PackageScanner
from guarddog.utils.archives import is_supported_archive
from guarddog.utils.package_info import get_package_info


class PypiPackageScanner(PackageScanner):
    def __init__(self) -> None:
        super().__init__(Analyzer(ECOSYSTEM.PYPI))

    def download_and_get_package_info(
        self, directory: str, package_name: str, version=None
    ) -> typing.Tuple[dict, str]:
        extract_dir = self.download_package(package_name, directory, version)
        return get_package_info(package_name), extract_dir

    def get_package_version(self, package_info: dict, requested_version=None):
        if requested_version is not None:
            return requested_version
        return package_info.get("info", {}).get("version")

    @staticmethod
    def _select_distribution(package_info: dict, version) -> typing.Optional[dict]:
        """Return the release file GuardDog scans for a version (first supported archive)."""
        releases = package_info.get("releases", {})
        if version is None:
            version = package_info.get("info", {}).get("version")
        for file in releases.get(version, []):
            if is_supported_archive(file["filename"]):
                return file
        return None

    def get_package_dist_path(self, package_info: dict, requested_version=None):
        distribution = self._select_distribution(package_info, requested_version)
        if distribution is None:
            return None
        return urlparse(distribution["url"]).path

    def get_package_inspector_url(self, name, version):
        package = quote(name, safe="")
        version = quote(str(version), safe="")
        return f"https://inspector.pypi.io/project/{package}/{version}/"

    def download_package(self, package_name, directory, version=None) -> str:
        """Downloads the PyPI distribution for a given package and version

        Args:
            package_name (str): name of the package
            directory (str): directory to download package to
            version (str): version of the package

        Raises:
            Exception: "Received status code: " + <not 200> + " from PyPI"
            Exception: "Version " + version + " for package " + package_name + " doesn't exist."
            Exception: "Compressed file for package does not exist."
            Exception: "Error retrieving package: " + <error message>
        Returns:
            Path where the package was extracted
        """

        data = get_package_info(package_name)
        releases = data["releases"]

        if version is None:
            version = data["info"]["version"]

        if version not in releases:
            raise Exception(
                f"Version {version} for package {package_name} doesn't exist."
            )

        distribution = self._select_distribution(data, version)
        if distribution is None:
            raise Exception(
                f"Compressed file for {package_name} does not exist on PyPI."
            )

        url = distribution["url"]
        _, file_extension = os.path.splitext(distribution["filename"])

        # Path to compressed package
        zippath = os.path.join(directory, package_name + file_extension)
        unzippedpath = os.path.join(directory, package_name)
        self.download_compressed(url, zippath, unzippedpath)

        return unzippedpath
