import logging
import os
import re
from typing import List

import pkg_resources
import requests
from packaging.specifiers import Specifier, Version

from guarddog.scanners.pypi_package_scanner import PypiPackageScanner
from guarddog.scanners.scanner import Dependency, DependencyVersion, ProjectScanner
from guarddog.utils.config import VERIFY_EXHAUSTIVE_DEPENDENCIES

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

            if not is_requirement:
                sanitized_lines.append("")  # empty line to keep the line number
                continue

            if "\\" in line:
                line = line.replace("\\", "")

            stripped_line = line.strip()
            sanitized_lines.append(stripped_line)

        return sanitized_lines

    def parse_requirements(self, raw_requirements: str) -> List[Dependency]:
        """
        Parses requirements.txt specification and finds all valid
        versions of each dependency

        Args:
            raw_requirements (str): contents of requirements.txt file

        Returns:
            dict: mapping of dependencies to valid versions
        """
        requirements = raw_requirements.splitlines()
        sanitized_requirements = self._sanitize_requirements(requirements)
        dependencies: List[Dependency] = []

        def get_matched_versions(versions: set[str], semver_range: str) -> set[str]:
            """
            Retrieves all versions that match a given semver selector
            """
            result = []

            # Filters to specified versions
            try:
                matching_versions = versions
                if semver_range:
                    spec = Specifier(semver_range)
                    matching_versions = set(spec.filter(versions))
                result = [Version(m) for m in matching_versions]
            except ValueError:
                # use it raw
                return set([semver_range])

            # If just the best matched version scan is required we only keep one
            if not VERIFY_EXHAUSTIVE_DEPENDENCIES and result:
                result = [sorted(result).pop()]

            return set([str(r) for r in result])

        def find_all_versions(package_name: str) -> set[str]:
            """
            This helper function retrieves all versions availables for the package
            """
            url = "https://pypi.org/pypi/%s/json" % (package_name,)
            log.debug(f"Retrieving PyPI package metadata information from {url}")
            response = requests.get(url)
            if response.status_code != 200:
                log.debug(f"No version available, status code {response.status_code}")
                return set()

            data = response.json()
            versions = set(sorted(data["releases"].keys()))
            log.debug(f"Retrieved versions {', '.join(versions)}")
            return versions

        def safe_parse_requirements(req):
            """
            This helper function yields one valid requirement line at a time
            """
            parsed = pkg_resources.parse_requirements(req)
            while True:
                try:
                    yield next(parsed)
                except StopIteration:
                    break
                except Exception as e:
                    log.error(
                        f"Error when parsing requirements, received error {str(e)}. This entry will be "
                        "ignored.\n"
                    )
                    yield None

        try:
            for requirement in safe_parse_requirements(sanitized_requirements):
                if requirement is None:
                    continue

                versions = get_matched_versions(
                    find_all_versions(requirement.project_name),
                    (
                        requirement.url
                        if requirement.url
                        else str(requirement.specifier)
                    ),
                )

                if len(versions) == 0:
                    log.error(
                        f"Package/Version {requirement.project_name} not on PyPI\n"
                    )
                    continue

                idx = next(
                    iter(
                        [
                            ix
                            for ix, line in enumerate(requirements)
                            if str(requirement) in line
                        ]
                    ),
                    0,
                )

                dep_versions = list(
                    map(
                        lambda d: DependencyVersion(version=d, location=idx + 1),
                        versions,
                    )
                )

                # find the dep with the same name or create a new one
                dep = next(
                    filter(
                        lambda d: d.name == requirement.project_name,
                        dependencies,
                    ),
                    None,
                )
                if not dep:
                    dep = Dependency(name=requirement.project_name, versions=set())
                    dependencies.append(dep)

                dep.versions.update(dep_versions)

        except Exception as e:
            log.error(f"Received error {str(e)}")

        return dependencies

    def find_requirements(self, directory: str) -> list[str]:
        requirement_files = []
        for root, dirs, files in os.walk(directory):
            for name in files:
                if re.match(r"^requirements(-dev)?\.txt$", name, flags=re.IGNORECASE):
                    requirement_files.append(os.path.join(root, name))
        return requirement_files
