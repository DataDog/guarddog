import json

import requests
from semantic_version import NpmSpec, Version

from guarddog.scanners import NPMPackageScanner
from guarddog.scanners.scanner import ProjectScanner

def find_all_versions(package_name: str, semver_range: str) -> set[str]:
    #  FIXME: handle cases where its a url, a git repo
    url = f"https://registry.npmjs.org/{package_name}"
    response = requests.get(url)
    if response.status_code != 200:
        return set()

    data = response.json()
    versions = list(data["versions"].keys())
    result = set()
    npm_spec = NpmSpec(semver_range)
    for v in versions:
        if Version(v) in npm_spec:
            result.add(v)
    return result




class NPMRequirementsScanner(ProjectScanner):
    """
    Scans all packages in the requirements.txt file of a project

    Attributes:
        package_scanner (PackageScanner): Scanner for individual packages
    """

    def __init__(self) -> None:
        super().__init__(NPMPackageScanner())

    def parse_requirements(self, raw_requirements: str) -> dict:
        package = json.loads(raw_requirements)
        dependencies = package["dependencies"]
        dev_dependencies = package["devDependencies"]

        merged = {}
        for package, selector in list(dependencies.items()) + list(dev_dependencies.items()):
            if package not in merged:
                merged[package] = set()
            merged[package].add(selector)

        results = {}
        for package, all_selectors in merged.items():
            versions = set()
            for selector in all_selectors:
                versions = versions.union(find_all_versions(package, selector))
            results[package] = versions
        return results
