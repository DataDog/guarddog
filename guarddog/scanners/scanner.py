import functools
import json
import os
import sys

import pathos  # type: ignore
import tempfile
from abc import abstractmethod

import requests

from guarddog.utils.archives import safe_extract


class Scanner:
    def __init__(self) -> None:
        pass

    @abstractmethod
    def scan_local(self, path, rules=None):
        pass


class ProjectScanner(Scanner):
    def __init__(self, package_scanner):
        super().__init__()
        self.package_scanner = package_scanner

    def _authenticate_by_access_token(self) -> tuple[str, str]:
        """
        Gives Github authentication through access token

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

    def scan_requirements(self, requirements: str, rules=None) -> dict:
        """
        Reads the requirements.txt file and scans each possible
        dependency and version

        Args:
            requirements (str): contents of requirements.txt file

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

        def get_package_results_helper(dependency, version):
            result = self.package_scanner.scan_remote(dependency, version, rules)
            return {'dependency': dependency, 'version': version, 'result': result}

        get_package_results = functools.partial(get_package_results_helper)
        dependencies = self.parse_requirements(requirements)
        params = []
        for dependency, versions in dependencies.items():
            if versions is None:
                params.append((dependency, None))  # this will cause scan_remote to use the latest version
            else:
                for version in versions:
                    params.append((dependency, version))
        pool = pathos.helpers.mp.Pool()
        project_results = pool.starmap(get_package_results, params)

        return project_results

    def scan_remote(self, url: str, branch: str, requirements_name: str) -> dict:
        """
        Scans remote requirements.txt file

        Args:
            url (str): url of the Github repo
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

    def scan_local(self, path, rules=None):
        """
        Scans a local requirements.txt file

        Args:
            path (str): path to requirements.txt file

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
                return self.scan_requirements(f.read(), rules)
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
            if path.endswith('.tar.gz') or path.endswith('.tgz') or path.endswith('.zip') or path.endswith('.whl'):
                with tempfile.TemporaryDirectory() as tmpdirname:
                    safe_extract(path, tmpdirname)
                    return self.analyzer.analyze_sourcecode(tmpdirname, rules=rules)
            elif os.path.isdir(path):
                return self.analyzer.analyze_sourcecode(path, rules=rules)
            else:
                raise Exception(f"Path {path} is not a directory nor an archive type supported by GuardDog.")
        raise Exception(f"Path {path} does not exist.")

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
