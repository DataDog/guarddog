import logging
import os
import pathlib
import typing
from urllib.parse import urlparse

from guarddog.analyzer.analyzer import Analyzer
from guarddog.ecosystems import ECOSYSTEM
from guarddog.scanners.scanner import PackageScanner

log = logging.getLogger("guarddog")


class GithubActionScanner(PackageScanner):
    def __init__(self) -> None:
        super().__init__(Analyzer(ECOSYSTEM.GITHUB_ACTION))

    def download_and_get_package_info(
        self, directory: str, package_name: str, version=None
    ) -> typing.Tuple[dict, str]:
        repo = self._get_repo(package_name)
        tarball_url = self._get_git_tarball_url(repo, version)

        log.debug(f"Downloading GitHub Action source from {tarball_url}")

        file_extension = pathlib.Path(tarball_url).suffix
        if file_extension == "":
            file_extension = ".zip"

        zippath = os.path.join(
            directory, package_name.replace("/", "-") + file_extension
        )
        unzippedpath = zippath.removesuffix(file_extension)
        self.download_compressed(tarball_url, zippath, unzippedpath)

        return {}, unzippedpath

    def _get_repo(self, url: str) -> str:
        parsed_url = urlparse(url)

        if parsed_url.hostname and parsed_url.hostname != "github.com":
            raise ValueError("Invalid GitHub repo URL: " + url)

        path = parsed_url.path.removesuffix(".git").strip("/")

        if path.count("/") != 1:
            raise ValueError("Invalid GitHub repo name: " + path)

        return path

    def _get_git_tarball_url(self, repo: str, version=None) -> str:
        if not version:
            return f"https://api.github.com/repos/{repo}/zipball"
        else:
            return f"https://github.com/{repo}/archive/refs/tags/{version}.zip"
