import logging
import os
import pathlib
import typing
from urllib.parse import urlparse

import requests

from guarddog.analyzer.analyzer import Analyzer
from guarddog.ecosystems import ECOSYSTEM
from guarddog.scanners.scanner import PackageScanner

log = logging.getLogger("guarddog")


class NPMPackageScanner(PackageScanner):
    def __init__(self) -> None:
        super().__init__(Analyzer(ECOSYSTEM.NPM))

    def download_and_get_package_info(self, directory: str, package_name: str, version=None) -> typing.Tuple[dict, str]:
        git_package_name = self._parse_git_url(package_name)

        if git_package_name != "":
            data, tarball_url = self._get_git_data_and_tarball_url(git_package_name, version)
        else:
            data, tarball_url = self._get_npm_data_and_tarball_url(package_name, version)

        log.debug(f"Downloading NPM package from {tarball_url}")
        file_extension = pathlib.Path(tarball_url).suffix
        zippath = os.path.join(directory, package_name.replace("/", "-") + file_extension)
        unzippedpath = zippath.removesuffix(file_extension)
        self.download_compressed(tarball_url, zippath, unzippedpath)

        return data, unzippedpath

    def _parse_git_url(self, package_name: str) -> str:
        parsed_url = urlparse(package_name)

        path = parsed_url.path.strip("/")  # trim leading and trailing slashes

        # TODO: support other git providers?
        if parsed_url.hostname == "github.com" and \
           path.endswith('.git') and \
           not path.startswith("@") and \
           path.count("/") == 1:
            return path.removesuffix(".git")

        return ""

    def _get_git_data_and_tarball_url(self, package_name: str, version=None) -> typing.Tuple[dict, str]:
        if version is None:
            return {}, f"https://github.com/{package_name}/archive/refs/heads/main.zip"
        else:
            return {}, f"https://github.com/{package_name}/archive/refs/tags/{version}.zip"

    def _get_npm_data_and_tarball_url(self, package_name: str, version=None) -> typing.Tuple[dict, str]:
        url = f"https://registry.npmjs.org/{package_name}"
        log.debug(f"Downloading NPM package metadata from {url}")
        response = requests.get(url)

        if response.status_code != 200:
            raise Exception("Received status code: " + str(response.status_code) + " from npm")
        data = response.json()
        if "name" not in data:
            raise Exception(f"Error retrieving package: {package_name}")

        # if version is none, we only scan the last package
        # TODO: figure logs and log it when we do that
        version = data["dist-tags"]["latest"] if version is None else version

        return data, data["versions"][version]["dist"]["tarball"]
