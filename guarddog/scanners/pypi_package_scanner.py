import os
import typing

from guarddog.analyzer.analyzer import Analyzer
from guarddog.ecosystems import ECOSYSTEM
from guarddog.scanners.scanner import PackageScanner
from guarddog.utils.archives import is_supported_archive
from guarddog.utils.package_info import get_package_info


class PypiPackageScanner(PackageScanner):
    def __init__(self) -> None:
        super().__init__(Analyzer(ECOSYSTEM.PYPI))

    def download_and_get_package_info(self, directory: str, package_name: str, version=None) -> typing.Tuple[dict, str]:
        extract_dir = self.download_package(package_name, directory, version)
        return get_package_info(package_name), extract_dir

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
            raise Exception(f"Version {version} for package {package_name} doesn't exist.")

        files = releases[version]
        url, file_extension = None, None

        for file in files:
            if is_supported_archive(file["filename"]):
                url = file["url"]
                _, file_extension = os.path.splitext(file["filename"])
                break

        if not (url and file_extension):
            raise Exception(f"Compressed file for {package_name} does not exist on PyPI.")

        # Path to compressed package
        zippath = os.path.join(directory, package_name + file_extension)
        unzippedpath = os.path.join(directory, package_name)
        self.download_compressed(url, zippath, unzippedpath)

        return unzippedpath
