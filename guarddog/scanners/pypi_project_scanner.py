import logging
import re
import sys

import pkg_resources
import requests

from guarddog.scanners.pypi_package_scanner import PypiPackageScanner
from guarddog.scanners.scanner import ProjectScanner

log = logging.getLogger("guarddog")


class PypiRequirementsScanner(ProjectScanner):
    """
    Scans all packages in the requirements.txt file of a project

    Attributes:
        package_scanner (PackageScanner): Scanner for individual packages
    """

    def __init__(self) -> None:
        super().__init__(PypiPackageScanner())

    def _sanitize_requirements(self, requirements: list[str]) -> list[str]:
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

    # FIXME: type return value properly to dict[str, set[str]]
    def parse_requirements(self, raw_requirements: str) -> dict:
        """
        Parses requirements.txt specification and finds all valid
        versions of each dependency

        Args:
            raw_requirements (List[str]): contents of requirements.txt file

        Returns:
            dict: mapping of dependencies to valid versions

            ex.
            {
                ....
                <dependency-name>: [0.0.1, 0.0.2, ...],
                ...
            }
        """
        requirements = raw_requirements.splitlines()

        def versions(package_name):
            url = "https://pypi.org/pypi/%s/json" % (package_name,)
            log.debug(f"Retrieving PyPI package metadata information from {url}")
            data = requests.get(url).json()
            versions = sorted(data["releases"].keys(), reverse=True)
            return versions

        sanitized_requirements = self._sanitize_requirements(requirements)

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
                        available_versions = versions(requirement.project_name)  # type: list[str]
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
                            matches = [re.search(version, candidate) for candidate in available_versions]
                            filtered_matches = list(filter(None, matches))
                            str_matches = [v.string for v in filtered_matches]
                            used_versions = set(str_matches)
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
