import concurrent.futures
import json
import logging
import os
from pathlib import Path
import shutil
import sys
import tempfile
import typing
from abc import abstractmethod
from concurrent.futures import ThreadPoolExecutor

import requests

from guarddog.analyzer.analyzer import Analyzer
from guarddog.ecosystems import ECOSYSTEM
from guarddog.utils.archives import safe_extract
from guarddog.utils.config import PARALLELISM
from guarddog.utils.diff import DirectoryDiff, SourceCodeDiffer

log = logging.getLogger("guarddog")


def noop(arg: typing.Any) -> None:
    pass


class ProjectScanner:
    def __init__(self, package_scanner):
        super().__init__()
        self.package_scanner = package_scanner

    def _authenticate_by_access_token(self) -> tuple[str, str]:
        """
        Gives GitHub authentication through access token

        Returns:
            tuple[str, str]: username, personal access token
        """

        user = os.getenv("GIT_USERNAME")
        personal_access_token = os.getenv("GH_TOKEN")
        if not user or not personal_access_token:
            log.error(
                """WARNING: Please set GIT_USERNAME (Github handle) and GH_TOKEN
                (generate a personal access token in Github settings > developer)
                as environment variables before proceeding."""
            )
            exit(1)
        return (user, personal_access_token)

    def scan_dependencies(
        self,
        dependencies: dict[str, set[str]],
        rules=None,
        callback: typing.Callable[[dict], None] = noop,
    ) :
        """
        scans each possible dependency and version supplied

        Args:
            dependencies (dict): a mapping of dependency name to set of versions used
            rules: list of rules to apply
            callback: callback to call for each result

        Returns:
            dict: mapping of dependencies to scan results

            ex.
            {
                ....
                <dependency-name>: {
                        issues: ...,
                        results: {
                            ...
                        }
                    },
                ...
            }
        """

        def scan_single_dependency(dependency, version):
            log.debug(f"Scanning {dependency} version {version}")
            result = self.package_scanner.scan_remote(dependency, version, rules)
            return {"dependency": dependency, "version": version, "result": result}

        num_workers = PARALLELISM

        log.info(
            f"Scanning using at most {num_workers} parallel worker threads\n"
        )
        with ThreadPoolExecutor(max_workers=num_workers) as pool:
            try:
                futures: typing.List[concurrent.futures.Future] = []
                for dependency, versions in dependencies.items():
                    assert versions is None or len(versions) > 0
                    if versions is None:
                        # this will cause scan_remote to use the latest version
                        futures.append(
                            pool.submit(scan_single_dependency, dependency, None)
                        )
                    else:
                        futures.extend(
                            map(
                                lambda version: pool.submit(
                                    scan_single_dependency, dependency, version
                                ),
                                versions,
                            )
                        )

                results = []
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if callback is not None:
                        callback(result)
                    results.append(result)
            except KeyboardInterrupt:
                log.warning("Received keyboard interrupt, cancelling scan\n")
                pool.shutdown(wait=False, cancel_futures=True)

        return results  # type: ignore

    def scan_remote(self, url: str, branch: str, requirements_name: str) -> dict:
        """
        Scans remote requirements.txt file

        Args:
            url (str): url of the GitHub repo
            branch (str): branch containing requirements.txt
            requirements_name (str, optional): name of requirements file.
                Defaults to "requirements.txt".

        Returns:
            dict: mapping of dependencies to scan results

            ex.
            {
                ....
                <dependency-name>: {
                        issues: ...,
                        results: {
                            ...
                        }
                    },
                ...
            }
        """

        token = self._authenticate_by_access_token()
        githubusercontent_url = url.replace("github", "raw.githubusercontent")

        req_url = f"{githubusercontent_url}/{branch}/{requirements_name}"
        resp = requests.get(url=req_url, auth=token)

        if resp.status_code == 200:
            dependencies = self.parse_requirements(resp.content.decode())
            return self.scan_dependencies(dependencies)
        else:
            log.error(
                f"{req_url} does not exist. Check your link or branch name."
            )
            sys.exit(255)

    def scan_local(
        self, path, rules=None, callback: typing.Callable[[dict], None] = noop
    ):
        """
        Scans a local requirements files (requirements.txt, package.json, etc.)

        Args:
            path (str): path to requirements file or directory to search
            rules: list of rules to apply
            callback: callback to call for each result

        Returns:
            dict: mapping of dependencies to scan results

            ex.
            {
                ....
                <dependency-name>: {
                        issues: ...,
                        results: {
                            ...
                        }
                    },
                ...
            }
        """

        requirement_paths = []

        try:
            if os.path.isfile(path):
                requirement_paths.append(path)
            elif os.path.isdir(path):
                requirement_paths.extend(self.find_requirements(path))
            else:
                raise ValueError(f"unable to find file or directory {path}")

            dependencies: dict[str, set[str]] = {}

            for req in requirement_paths:
                with open(req, "r") as f:
                    self._extend_requirements(dependencies, self.parse_requirements(f.read()))
            self.scan_dependencies(dependencies, rules, callback)
            return dependencies
        except Exception as e:
            log.error(f"Received {e}")
            sys.exit(255)

    @abstractmethod
    def parse_requirements(
        self, raw_requirements: str
    ) -> dict[str, set[str]]:  # returns { package: version }
        pass

    @abstractmethod
    def find_requirements(
            self, directory: str,
    ) -> list[str]:  # returns paths of files
        pass

    @staticmethod
    def _extend_requirements(reqs_a : dict[str, set[str]], reqs_b: dict[str, set[str]]):
        for name, versions in reqs_b.items():
            if name not in reqs_a:
                reqs_a[name] = versions
            else:
                reqs_a[name].update(versions)


class PackageScanner:
    """
    Scans package for attack vectors based on source code and metadata rules

    Attributes:
        analyzer (Analyzer): Analyzer for source code and metadata rules
    """

    def __init__(self, analyzer: Analyzer):
        super().__init__()
        self.analyzer = analyzer

    @abstractmethod
    def ecosystem(self) -> ECOSYSTEM:
        """
        Return the package ecosystem a `PackageScanner` is intended for.
        """
        raise NotImplementedError("ecosystem is not implemented")

    def scan_local(
        self, path, rules=None, callback: typing.Callable[[dict], None] = noop
    ) -> dict:
        """
        Scans local package

        Args:
            path (str): Path to the directory containing the package to analyze
            rules (set, optional): Set of rule names to use. Defaults to all rules.
            callback (typing.Callable[[dict], None], optional): Callback to apply to Analyzer output

        Raises:
            Exception: Analyzer exception

        Returns:
            dict: Analyzer output with rules to results mapping
        """

        if rules is not None:
            rules = set(rules)

        results = self.analyzer.analyze_sourcecode(path, rules=rules)
        callback(results)

        return results

    @abstractmethod
    def download_and_get_package_info(
        self, directory: str, package_name: str, version=None
    ) -> typing.Tuple[dict, str]:
        raise NotImplementedError("download_and_get_package_info is not implemented")

    def _scan_remote(
        self, name, base_dir, version=None, rules=None, write_package_info=False
    ):
        directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), base_dir)

        file_path = None
        package_info = None
        try:
            package_info, file_path = self.download_and_get_package_info(
                directory, name, version
            )
        except Exception as e:
            log.debug("Unable to download package, ignoring: " + str(e))
            return {"issues": 0, "errors": {"download-package": str(e)}}

        results = self.analyzer.analyze(file_path, package_info, rules, name, version)
        if write_package_info:
            package_name = name.replace("/", "-")
            suffix = (
                f"{package_name}-{version}" if version is not None else package_name
            )
            with open(
                os.path.join(results["path"], f"package_info-{suffix}.json"), "w"
            ) as file:
                file.write(json.dumps(package_info))

        return results

    def scan_remote(
        self, name, version=None, rules=None, base_dir=None, write_package_info=False
    ):
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
        if base_dir is not None:
            return self._scan_remote(name, base_dir, version, rules, write_package_info)

        with tempfile.TemporaryDirectory() as tmpdirname:
            # Directory to download compressed and uncompressed package
            return self._scan_remote(
                name, tmpdirname, version, rules, write_package_info
            )

    def scan_diff(self, name, old_version, new_version=None, rules=None) -> dict:
        """
        Perform a diff scan between the two given versions.

        Args:
            * `name` (str): The name of the package as found on PyPI
            * `old_version` (str): The version of the package to diff against
            * `new_version` (str): The version of the package to scan
            * `rules` (set, optional): The set of rule names to use (default: all rules used)

        Returns:
            dict: A `dict` mapping rule names to the findings the rule produced during analysis
        """
        def release_temp_dirs(temp_dirs: list) -> None:
            for dir in temp_dirs:
                dir.cleanup()

        try:
            source_differ = SourceCodeDiffer.from_ecosystem(self.ecosystem())
        except Exception as e:
            log.debug(f"Failed to initialize source file differ: {e}")
            return {"issues": 0, "errors": {"diff-scan": str(e)}}

        old_version_dir = tempfile.TemporaryDirectory()
        new_version_dir = tempfile.TemporaryDirectory()

        try:
            _, old_version_path = self.download_and_get_package_info(
                old_version_dir.name, name, old_version
            )
            _, new_version_path = self.download_and_get_package_info(
                new_version_dir.name, name, new_version
            )
        except Exception as e:
            release_temp_dirs([old_version_dir, new_version_dir])
            log.debug("Unable to download package, ignoring: " + str(e))
            return {"issues": 0, "errors": {"download-package": str(e)}}

        diff = DirectoryDiff.from_directories(Path(old_version_path), Path(new_version_path))
        diff_dir = tempfile.TemporaryDirectory()

        for path in diff.changed:
            old_path = diff.left / path
            new_path = diff.right / path
            diff_path = Path(diff_dir.name) / path
            os.makedirs(diff_path.parent, exist_ok=True)

            try:
                with open(old_path, 'rb') as f:
                    old_source = f.read()
                with open(new_path, 'rb') as f:
                    new_source = f.read()
                source_diff = source_differ.get_diff(old_source, new_source)
                with open(diff_path, 'wb') as f:
                    f.write(source_diff)
            except Exception as e:
                log.debug(f"Failed to diff file {path}: {e}")
                shutil.copy(new_path, diff_path)

        for path in diff.added:
            src_path = diff.right / path
            dst_path = Path(diff_dir.name) / path
            if src_path.is_dir():
                shutil.copytree(src_path, dst_path, dirs_exist_ok=True)
            elif src_path.is_file():
                os.makedirs(dst_path.parent, exist_ok=True)
                shutil.copy(src_path, dst_path)

        results = self.analyzer.analyze_sourcecode(diff_dir.name, rules=rules)

        release_temp_dirs([old_version_dir, new_version_dir, diff_dir])

        return results

    def download_compressed(self, url, archive_path, target_path):
        """Downloads a compressed file and extracts it

        Args:
            url (str): download link
            archive_path (str): path to download compressed file
            target_path (str): path to unzip compressed file
        """

        log.debug(f"Downloading package archive from {url} into {target_path}")
        response = requests.get(url, stream=True)

        with open(archive_path, "wb") as f:
            f.write(response.raw.read())

        try:
            safe_extract(archive_path, target_path)
            log.debug(f"Successfully extracted files to {target_path}")
        finally:
            log.debug(f"Removing temporary archive file {archive_path}")
            os.remove(archive_path)
