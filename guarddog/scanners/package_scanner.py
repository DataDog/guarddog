import json
import os
import tempfile

import requests
import tarsafe  # type:ignore

from guarddog.analyzer.analyzer import Analyzer
from guarddog.scanners.scanner import Scanner
from guarddog.utils.archives import safe_extract
from guarddog.utils.package_info import get_package_info


class PackageScanner(Scanner):
    """
    Scans package for attack vectors based on source code and metadata rules

    Attributes:
        analyzer (Analyzer): Analyzer for source code and metadata rules
    """

    def __init__(self) -> None:
        self.analyzer = Analyzer()
        super(Scanner)

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

    def _scan_remote(self, name, base_dir, version=None, rules=None, write_package_info=False):
        directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), base_dir)
        file_path = os.path.join(directory, name)

        self.download_package(name, directory, version)

        package_info = get_package_info(name)

        results = self.analyzer.analyze(file_path, package_info, rules)
        if write_package_info:
            suffix = f"{name}-{version}" if version is not None else name
            with open(os.path.join(results["path"], f'package_info-{suffix}.json'), "w") as file:
                file.write(json.dumps(package_info))

        return results

    def scan_remote(self, name, version=None, rules=None, base_dir=None, write_package_info=False):
        """
        Scans a remote package

        Args:
            * `name` (str): name of the package on PyPI
            * `version` (str, optional): version of package (ex. 0.0.1). If not specified, the latest version is
            assumed.
            * `rules` (set, optional): Set of rule names to use. Defaults to all rules.
            * `base_dir` (str, optional): directory to use to download package to. If not specified, a temporary folder
            is created and cleaned up automatically. If not specified, the provided directory is not removed after the
            scan.
            * `write_package_info` (bool, default False): if set to true, the result of the PyPI metadata API is written
             to a json file

        Raises:
            Exception: Analyzer exception

        Returns:
            dict: Analyzer output with rules to results mapping
        """
        if (base_dir is not None):
            return self._scan_remote(name, base_dir, version, rules, write_package_info)

        with tempfile.TemporaryDirectory() as tmpdirname:
            # Directory to download compressed and uncompressed package
            return self._scan_remote(name, tmpdirname, version, rules, write_package_info)

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

    def download_compressed(self, url, archive_path, target_path):
        """Downloads a compressed file and extracts it

        Args:
            url (str): download link
            archive_path (str): path to download compressed file
            target_path (str): path to unzip compressed file
        """

        response = requests.get(url, stream=True)

        with open(archive_path, "wb") as f:
            f.write(response.raw.read())

        try:
            safe_extract(archive_path, target_path)
        finally:
            os.remove(archive_path)
