import concurrent.futures
import json
import logging
import multiprocessing
import os
import sys
import tempfile
import typing
from abc import abstractmethod
from concurrent.futures import ThreadPoolExecutor

import requests

from guarddog.utils.archives import safe_extract

log = logging.getLogger("guarddog")


def noop(arg: typing.Any) -> None:
    pass


class Scanner:
    def __init__(self) -> None:
        pass

    @abstractmethod
    def scan_local(self, path, rules=None, callback: typing.Callable[[dict], None] = noop):
        pass


class ProjectScanner(Scanner):
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
            print(
                """WARNING: Please set GIT_USERNAME (Github handle) and GH_TOKEN
                (generate a personal access token in Github settings > developer)
                as environment variables before proceeding."""
            )
            exit(1)
        return (user, personal_access_token)

    def scan_requirements(self, requirements: str, rules=None, callback: typing.Callable[[dict], None] = noop) -> dict:
        """
        Reads the requirements.txt file and scans each possible
        dependency and version

        Args:
            requirements (str): contents of requirements.txt file
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
            return {
                'dependency': dependency,
                'version': version,
                'result': result
            }

        dependencies = self.parse_requirements(requirements)

        num_workers = multiprocessing.cpu_count()
        if os.environ.get("GUARDDOG_PARALLELISM") is not None:
            num_workers = int(os.environ["GUARDDOG_PARALLELISIM"])

        sys.stderr.write(f"Scanning using at most {num_workers} parallel worker threads\n")
        sys.stderr.flush()
        with ThreadPoolExecutor(max_workers=num_workers) as pool:
            try:
                futures: typing.List[concurrent.futures.Future] = []
                for dependency, versions in dependencies.items():
                    assert versions is None or len(versions) > 0
                    if versions is None:
                        # this will cause scan_remote to use the latest version
                        futures.append(pool.submit(scan_single_dependency, dependency, None))
                    else:
                        futures.extend(map(
                            lambda version: pool.submit(scan_single_dependency, dependency, version),
                            versions
                        ))

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
            return self.scan_requirements(resp.content.decode())
        else:
            sys.stdout.write(f"{req_url} does not exist. Check your link or branch name.")
            sys.exit(255)

    def scan_local(self, path, rules=None, callback: typing.Callable[[dict], None] = noop):
        """
        Scans a local requirements.txt file

        Args:
            path (str): path to requirements.txt file
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

        try:
            with open(path, "r") as f:
                return self.scan_requirements(f.read(), rules, callback)
        except Exception as e:
            sys.stdout.write(f"Received {e}")
            sys.exit(255)

    @abstractmethod
    def parse_requirements(self, param: str) -> dict[str, set[str]]:  # returns { package: version }
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

    def scan_local(self, path, rules=None, callback: typing.Callable[[dict], None] = noop) -> dict:
        """
        Scans local package

        Args:
            path (str): path to package
            rules (set, optional): Set of rule names to use. Defaults to all rules.

        Raises:
            Exception: Analyzer exception

        Returns:
            dict: Analyzer output with rules to results mapping
            rules: rules to apply
            callback: callback to call for each result
        """

        if rules is not None:
            rules = set(rules)

        if not os.path.exists(path):
            raise Exception(f"Path {path} does not exist.")

        if any(path.endswith(ext) for ext in ('.tar.gz', '.tgz', '.zip', '.whl')):
            with tempfile.TemporaryDirectory() as tmpdirname:
                safe_extract(path, tmpdirname)
                return self.analyzer.analyze_sourcecode(tmpdirname, rules=rules)

        if os.path.isdir(path):
            return self.analyzer.analyze_sourcecode(path, rules=rules)

        raise Exception(f"Path {path} is not a directory nor an archive type supported by GuardDog.")

    @abstractmethod
    def download_and_get_package_info(self, directory: str, package_name: str, version=None) -> typing.Tuple[dict, str]:
        raise NotImplementedError('download_and_get_package_info is not implemented')

    def _scan_remote(self, name, base_dir, version=None, rules=None, write_package_info=False):
        directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), base_dir)

        file_path = None
        package_info = None
        try:
            package_info, file_path = self.download_and_get_package_info(directory, name, version)
        except Exception as e:
            log.debug("Unable to download package, ignoring: " + str(e))
            return {'issues': 0, 'errors': {'download-package': str(e)}}

        results = self.analyzer.analyze(file_path, package_info, rules, name, version)
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
        if base_dir is not None:
            return self._scan_remote(name, base_dir, version, rules, write_package_info)

        with tempfile.TemporaryDirectory() as tmpdirname:
            # Directory to download compressed and uncompressed package
            return self._scan_remote(name, tmpdirname, version, rules, write_package_info)

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
