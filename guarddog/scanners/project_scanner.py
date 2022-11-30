import functools
import os
import re
import sys
from pprint import pprint

import pathos
import pkg_resources
import requests
from packaging.requirements import InvalidRequirement

from guarddog.scanners.package_scanner import PackageScanner
from guarddog.scanners.scanner import Scanner


class RequirementsScanner(Scanner):
    """
    Scans all packages in the requirements.txt file of a project

    Attributes:
        package_scanner (PackageScanner): Scanner for individual packages
    """

    def __init__(self) -> None:
        self.package_scanner = PackageScanner()
        super(Scanner)

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

    def sanitize_requirements(self, requirements) -> list[str]:
        """
        Filters out non-requirement specifications from a requirements specification

        Args:
            requirements (str): PEP440 styled dependency specification text

        Returns:
            list[str]: sanitized lines containing only version specifications
        """

        sanitized_lines = []

        for line in requirements:
            is_requirement = re.match(r"\w", line)
            if is_requirement:
                if "\\" in line:
                    line = line.replace("\\", "")
                    
                stripped_line = line.strip()
                if len(stripped_line) > 0:
                    sanitized_lines.append(stripped_line)

        return sanitized_lines

    def parse_requirements(self, requirements) -> dict:
        """
        Parses requirements.txt specification and finds all valid
        versions of each dependency

        Args:
            requirements (List[str]): contents of requirements.txt file

        Returns:
            dict: mapping of dependencies to valid versions

            ex.
            {
                ....
                <dependency-name>: [0.0.1, 0.0.2, ...],
                ...
            }
        """

        def versions(package_name):
            url = "https://pypi.org/pypi/%s/json" % (package_name,)
            data = requests.get(url).json()
            versions = sorted(data["releases"].keys(), reverse=True)
            return versions

        sanitized_requirements = self.sanitize_requirements(requirements)

        dependencies = {}

        def safe_parse_requirements(req):
            parsed = pkg_resources.parse_requirements(req)
            while True:
                try:
                    yield next(parsed)
                except StopIteration:
                    break
                except Exception as e:
                    sys.stderr.write(f"Error when parsing requirements, received error {str(e)}. This entry will be "
                                     "ignored.\n")
                    yield None

        try:
            for requirement in safe_parse_requirements(sanitized_requirements):
                if requirement is None:
                    continue
                valid_versions = None
                project_exists_on_pypi = True
                for spec in requirement.specs:
                    qualifier, version = spec

                    try:
                        available_versions = versions(requirement.project_name)
                    except Exception:
                        sys.stderr.write(f"Package {requirement.project_name} not on PyPI\n")
                        project_exists_on_pypi = False
                        continue

                    used_versions = None

                    match qualifier:
                        case ">":
                            used_versions = {v for v in available_versions if v > version}
                        case "<":
                            used_versions = {v for v in available_versions if v < version}
                        case ">=":
                            used_versions = {v for v in available_versions if v >= version}
                        case "<=":
                            used_versions = {v for v in available_versions if v <= version}
                        case "==":
                            matching_versions = filter(
                                lambda v: v is not None,
                                (re.search(version, candidate) for candidate in available_versions),
                            )
                            matching_versions = set(match.string for match in matching_versions)
                            used_versions = matching_versions
                        case "~=":
                            prefix = "".join(version.split(".")[:-1])
                            for available_version in available_versions:  # sorted decreasing
                                if available_version >= version and available_version.startswith(prefix):
                                    used_versions = set(available_version)
                                    break
                        case _:
                            sys.stderr.write(f"Unknown qualifier: {qualifier}")
                            continue

                    if valid_versions is None:
                        valid_versions = used_versions
                    else:
                        valid_versions = valid_versions & used_versions

                if project_exists_on_pypi:
                    dependencies[requirement.project_name] = valid_versions
        except Exception as e:
            sys.stderr.write(f"Received error {str(e)}")

        return dependencies

    def scan_requirements(self, requirements):
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
            result = self.package_scanner.scan_remote(dependency, version)
            return {'dependency': dependency, 'version': version, 'result': result}

        get_package_results = functools.partial(get_package_results_helper)
        dependencies = self.parse_requirements(requirements)
        params = []
        for dependency, versions in dependencies.items():
            if versions is None:
                params.append((dependency, None)) # this will cause scan_remote to use the latest version
            else:
                for version in versions:
                    params.append((dependency, version))
        pool = pathos.helpers.mp.Pool()
        project_results = pool.starmap(get_package_results, params)

        return project_results

    def scan_local(self, path):
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
                return self.scan_requirements(f.readlines())
        except Exception as e:
            sys.stdout.write(f"Received {e}")
            sys.exit(255)

    def scan_remote(self, url, branch, requirements_name="requirements.txt"):
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
            return self.scan_requirements(resp.content.decode().splitlines())
        else:
            sys.stdout.write(f"{req_url} does not exist. Check your link or branch name.")
            sys.exit(255)
