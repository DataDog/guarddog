import json

import requests
from semantic_version import NpmSpec, Version  # type:ignore

from guarddog.scanners.npm_package_scanner import NPMPackageScanner
from guarddog.scanners.scanner import ProjectScanner


def find_all_versions(package_name: str, semver_range: str) -> set[str]:
    url = f"https://registry.npmjs.org/{package_name}"
    response = requests.get(url)
    if response.status_code != 200:
        return set()

    data = response.json()
    versions = list(data["versions"].keys())
    result = set()
    try:
        npm_spec = NpmSpec(semver_range)
    except ValueError:  # not a semver range, let's keep it raw
        result.add(semver_range)
        return result
    for v in versions:
        if Version(v) in npm_spec:
            result.add(v)
    return result


class NPMRequirementsScanner(ProjectScanner):
    """
    Scans all packages in the package.json file of a project

    Attributes:
        package_scanner (PackageScanner): Scanner for individual packages
    """

    def __init__(self) -> None:
        super().__init__(NPMPackageScanner())

    def parse_requirements(self, raw_requirements: str) -> dict:
        package = json.loads(raw_requirements)
        dependencies = package["dependencies"] if "dependencies" in package else {}
        dev_dependencies = package["devDependencies"] if "devDependencies" in package else {}

        merged = {}  # type: dict[str, set[str]]
        for package, selector in list(dependencies.items()) + list(dev_dependencies.items()):
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
