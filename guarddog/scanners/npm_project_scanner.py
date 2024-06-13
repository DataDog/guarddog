import json
import logging
import requests
from semantic_version import NpmSpec, Version  # type:ignore

from guarddog.utils.config import VERIFY_EXHAUSTIVE_DEPENDENCIES
from guarddog.scanners.npm_package_scanner import NPMPackageScanner
from guarddog.scanners.scanner import ProjectScanner

log = logging.getLogger("guarddog")


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

        def get_matched_versions(versions: set[str], semver_range: str) -> set[str]:
            """
            Retrieves all versions that match a given semver selector
            """
            result = []

            # Filters to specified versions
            try:
                spec = NpmSpec(semver_range)
                result = [Version(m) for m in versions if spec.match(Version(m))]
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
            url = f"https://registry.npmjs.org/{package_name}"
            log.debug(f"Retrieving npm package metadata from {url}")
            response = requests.get(url)
            if response.status_code != 200:
                log.debug(f"No version available, status code {response.status_code}")
                return set()

            data = response.json()
            versions = set(data["versions"].keys())
            log.debug(f"Retrieved versions {', '.join(versions)}")
            return versions

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
                versions = versions.union(
                    get_matched_versions(find_all_versions(package), selector)
                )
            if len(versions) == 0:
                log.error(f"Package/Version {package} not on NPM\n")
                continue

            results[package] = versions
        return results
