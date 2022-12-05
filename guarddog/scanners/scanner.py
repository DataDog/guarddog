import json
import os
import shutil
import tempfile
from abc import abstractmethod

import requests


class Scanner:
    def __init__(self) -> None:
        pass


class PackageScanner(Scanner):
    """
    Scans package for attack vectors based on source code and metadata rules

    Attributes:
        analyzer (Analyzer): Analyzer for source code and metadata rules
    """

    def __init__(self, analyzer):
        super().__init__()
        self.analyzer = analyzer

    @abstractmethod
    def scan_local(self, path, rules=None) -> dict:
        raise NotImplementedError('scan_local is not implemented')

    @abstractmethod
    def download_and_get_package_info(self, directory: str, package_name: str, version=None) -> dict:
        raise NotImplementedError('download_and_get_package_info is not implemented')

    def _scan_remote(self, name, base_dir, version=None, rules=None, write_package_info=False):
        directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), base_dir)
        file_path = os.path.join(directory, name)

        package_info = self.download_and_get_package_info(directory, name, version)

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
            * `version` (str, optional): version of package (ex. 0.0.1). If not specified, the latest version is assumed
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

    def download_compressed(self, url, zippath, unzippedpath):
        """Downloads a compressed file and extracts it

        Args:
            url (str): download link
            zippath (str): path to download compressed file
            unzippedpath (str): path to unzip compressed file
        """

        response = requests.get(url, stream=True)

        with open(zippath, "wb") as f:
            f.write(response.raw.read())

        shutil.unpack_archive(zippath, unzippedpath)
        os.remove(zippath)
