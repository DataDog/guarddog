import logging
import os
import re
import pkg_resources
import requests
import toml
from packaging.specifiers import Specifier, Version

from guarddog.scanners.pypi_package_scanner import PypiPackageScanner
from guarddog.scanners.scanner import ProjectScanner
from guarddog.utils.config import VERIFY_EXHAUSTIVE_DEPENDENCIES

log = logging.getLogger("guarddog")


class UVLockScanner(ProjectScanner):
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
            stripped_line = line.strip()
            if not stripped_line or stripped_line.startswith("#"):
                continue
            if re.match(r"^[a-zA-Z0-9_\-\.]+==[a-zA-Z0-9_\-\.]+$", stripped_line):
                sanitized_lines.append(stripped_line)
        else:
            log.warning(f"Skipping invalid requirement line: {line}")

        return sanitized_lines

    def parse_requirements(self, raw_requirements: str) -> dict[str, set[str]]:
        """
        Parses uv.lock specification and finds all valid
        versions of each dependency

        Args:
            requirements (str): contents of uv.lock file

        Returns:
            dict: mapping of dependencies to valid versions

            ex.
            {
                ....
                <dependency-name>: [0.0.1, 0.0.2, ...],
                ...
            }
        """
        lock_data = toml.loads(raw_requirements)
        requirements = []
        for package in lock_data.get("package", []):
            name = package.get("name")
            version = package.get("version")
            if name and version:
                requirements.append(f"{name}=={version}")
        sanitized_requirements = self._sanitize_requirements(requirements)
        dependencies = {}

        def get_matched_versions(versions: set[str], semver_range: str) -> set[str]:
            """
            Retrieves all versions that match a given semver selector
            """
            result = []

            # Filters to specified versions
            try:
                spec = Specifier(semver_range)
                result = [Version(m) for m in spec.filter(versions)]
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

        def safe_parse_requirements(requirements):
            """
            This helper function yields one valid requirement line at a time
            """
            parsed = pkg_resources.parse_requirements(requirements)
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

                dependencies[requirement.project_name] = versions
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
