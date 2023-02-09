import logging
import os
import pathlib
from urllib.parse import urlparse

import requests

from guarddog.analyzer.analyzer import Analyzer
from guarddog.ecosystems import ECOSYSTEM
from guarddog.scanners.scanner import PackageScanner

log = logging.getLogger("guarddog")


class NPMPackageScanner(PackageScanner):
    def __init__(self) -> None:
        super().__init__(Analyzer(ECOSYSTEM.NPM))

    def download_and_get_package_info(self, directory: str, package_name: str, version=None) -> dict:
        git_target = None
        if urlparse(package_name).hostname is not None and package_name.endswith('.git'):
            git_target = package_name

        if not package_name.startswith("@") and package_name.count("/") == 1:
            git_target = f"https://github.com/{package_name}.git"

        if git_target is not None:
            raise Exception("Git targets are not yet supported for npm")

        url = f"https://registry.npmjs.org/{package_name}"
        log.debug(f"Downloading NPM package from {url}")
        response = requests.get(url)

        if response.status_code != 200:
            raise Exception("Received status code: " + str(response.status_code) + " from npm")
        data = response.json()
        if "name" not in data:
            raise Exception(f"Error retrieving package: {package_name}")
        # if version is none, we only scan the last package
        # TODO: figure logs and log it when we do that
        version = data["dist-tags"]["latest"] if version is None else version

        details = data["versions"][version]

        tarball_url = details["dist"]["tarball"]
        file_extension = pathlib.Path(tarball_url).suffix
        zippath = os.path.join(directory, package_name + file_extension)
        unzippedpath = zippath.removesuffix(file_extension)
        self.download_compressed(tarball_url, zippath, unzippedpath)

        return data
