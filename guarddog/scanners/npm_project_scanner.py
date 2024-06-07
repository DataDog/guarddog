import json
import logging
import os
import requests
from semantic_version import NpmSpec, Version  # type:ignore

from guarddog.scanners.npm_package_scanner import NPMPackageScanner
from guarddog.scanners.scanner import ProjectScanner

log = logging.getLogger("guarddog")
# This flag spedificies if an analysis of all posible versions is required
VERIFY_ALL_DEPENDENCIES = os.environ.get("GUARDDOG_VERIFY_ALL_DEPENDENCIES", False)


class NPMRequirementsScanner(ProjectScanner):
    """
    Scans all packages in the package.json file of a project

    Attributes:
        package_scanner (PackageScanner): Scanner for individual packages
    """

    def __init__(self) -> None:
        super().__init__(NPMPackageScanner())

    def parse_requirements(self, raw_requirements: str) -> dict:
        """
        Parses requirements.txt specification and finds all valid
        versions of each dependency

        Args:
            raw_requirements (str): contents of package file

        Returns:
            dict: mapping of dependencies to valid versions

            ex.
            {
                ....
                <dependency-name>: [0.0.1, 0.0.2, ...],
                ...
            }
        """
        package = json.loads(raw_requirements)
        dependencies = package["dependencies"] if "dependencies" in package else {}
        dev_dependencies = (
            package["devDependencies"] if "devDependencies" in package else {}
        )

        def find_all_versions(package_name: str, semver_range: str) -> set[str]:
            """
            This helper function retrieves all versions matching the selector
            """
            url = f"https://registry.npmjs.org/{package_name}"
            log.debug(f"Retrieving npm package metadata from {url}")
            response = requests.get(url)
            if response.status_code != 200:
                log.debug(f"No version available, status code {response.status_code}")
                return set()

            data = response.json()
            versions = list(data["versions"].keys())
            log.debug(f"Retrieved versions {', '.join(versions)}")
            result = set()
            try:
                npm_spec = NpmSpec(semver_range)
            except ValueError:  # not a semver range, let's keep it raw
                result.add(semver_range)
                return result
            for v in versions:
                if Version(v) in npm_spec:
                    result.add(v)

            # If just the best matched version scan is required we only keep one
            if not VERIFY_ALL_DEPENDENCIES and result:
                result = set([sorted(result).pop()])

            return result

        merged = {}  # type: dict[str, set[str]]
        for package, selector in list(dependencies.items()) + list(
            dev_dependencies.items()
        ):
            if package not in merged:
                merged[package] = set()
            merged[package].add(selector)

        results = {}
        for package, all_selectors in merged.items():
            versions = set()  # type: set[str]
            for selector in all_selectors:
                versions = versions.union(find_all_versions(package, selector))
            if len(versions) > 0:
                results[package] = versions
        return results
