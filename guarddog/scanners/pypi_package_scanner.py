import os
import tarsafe  # type: ignore
import tempfile
import requests

from guarddog.analyzer.analyzer import Analyzer
from guarddog.scanners.scanner import PackageScanner


def get_package_info(name: str) -> dict:
    """Gets metadata and other information about package

    Args:
        name (str): name of the package

    Raises:
        Exception: "Received status code: " + str(response.status_code) + " from PyPI"
        Exception: "Error retrieving package: " + data["message"]

    Returns:
        json: package attributes and values
    """

    url = "https://pypi.org/pypi/%s/json" % (name,)
    response = requests.get(url)

    # Check if package file exists
    if response.status_code != 200:
        raise Exception("Received status code: " + str(response.status_code) + " from PyPI")

    data = response.json()

    # Check for error in retrieving package
    if "message" in data:
        raise Exception("Error retrieving package: " + data["message"])

    return data


class PypiPackageScanner(PackageScanner):
    def __init__(self) -> None:
        super().__init__(Analyzer("pypi"))

    def scan_local(self, path, rules=None) -> dict:
        """
        Scans local package

        Args:
            path (str): path to package
            rules (set, optional): Set of rule names to use. Defaults to all rules.

        Raises:
            Exception: Analyzer exception

        Returns:
            dict: Analyzer output with rules to results mapping
        """

        if rules is not None:
            rules = set(rules)

        if os.path.exists(path):
            if path.endswith('.tar.gz'):
                with tempfile.TemporaryDirectory() as tmpdirname:
                    tarsafe.open(path).extractall(tmpdirname)
                    return self.analyzer.analyze_sourcecode(tmpdirname, rules=rules)
            elif os.path.isdir(path):
                return self.analyzer.analyze_sourcecode(path, rules=rules)
            else:
                raise Exception(f"Path {path} is not a directory nor a tar.gz archive.")
        raise Exception(f"Path {path} does not exist.")

    def download_and_get_package_info(self, directory: str, package_name: str, version=None):
        self.download_package(package_name, directory, version)
        return get_package_info(package_name)

    def download_package(self, package_name, directory, version=None) -> None:
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
            None
        """

        data = get_package_info(package_name)
        releases = data["releases"]

        if version is None:
            version = data["info"]["version"]

        if version in releases:
            files = releases[version]

            url = None
            file_extension = None

            for file in files:
                # Store url to compressed package and appropriate file extension
                if file["filename"].endswith(".tar.gz"):
                    url = file["url"]
                    file_extension = ".tar.gz"

                if file["filename"].endswith(".egg") or file["filename"].endswith(".whl") \
                        or file["filename"].endswith(".zip"):
                    url = file["url"]
                    file_extension = ".zip"

            if url and file_extension:
                # Path to compressed package
                zippath = os.path.join(directory, package_name + file_extension)
                unzippedpath = zippath.removesuffix(file_extension)

                self.download_compressed(url, zippath, unzippedpath)
            else:
                raise Exception(f"Compressed file for {package_name} does not exist on PyPI.")
        else:
            raise Exception("Version " + version + " for package " + package_name + " doesn't exist.")
