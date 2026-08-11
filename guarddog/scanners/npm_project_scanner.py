import json
import logging
import os
import re
import typing
from typing import List, Tuple

from guarddog.scanners.npm_package_scanner import NPMPackageScanner
from guarddog.scanners.scanner import (
    Dependency,
    DependencyFile,
    DependencyVersion,
    ProjectScanner,
    noop,
)
from guarddog.utils.config import VERIFY_EXHAUSTIVE_DEPENDENCIES
from guarddog.utils.npm import (
    find_all_versions,
    get_matched_versions,
    resolve_npm_alias,
)

log = logging.getLogger("guarddog")


class NPMRequirementsScanner(ProjectScanner):
    """
    Scans all packages in the package.json file of a project

    Attributes:
        package_scanner (PackageScanner): Scanner for individual packages
    """

    def __init__(self) -> None:
        super().__init__(NPMPackageScanner())

    def parse_requirements(
        self, raw_requirements: str, exclude_dev: bool = False
    ) -> List[Dependency]:
        """
        Parses requirements.txt specification and finds all valid
        versions of each dependency

        Args:
            raw_requirements (str): contents of package file
            exclude_dev (bool): when True, devDependencies are skipped and
                only production dependencies are scanned. Defaults to False
                (scan all dependencies).

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
        dependencies_attr = package["dependencies"] if "dependencies" in package else {}
        dev_dependencies_attr = (
            {} if exclude_dev else package.get("devDependencies", {})
        )
        raw_requirement_lines = raw_requirements.splitlines()

        merged = {}  # type: dict[str, set[str]]
        merged_original_names = {}  # type: dict[str, set[str]]
        for package, selector in list(dependencies_attr.items()) + list(
            dev_dependencies_attr.items()
        ):
            resolved_package, resolved_selector = resolve_npm_alias(package, selector)
            if resolved_package not in merged:
                merged[resolved_package] = set()
            merged[resolved_package].add(resolved_selector)

            if resolved_package not in merged_original_names:
                merged_original_names[resolved_package] = set()
            merged_original_names[resolved_package].add(package)

        dependencies: List[Dependency] = []
        for package, all_selectors in merged.items():
            versions = set()  # type: set[str]
            for selector in all_selectors:
                versions = versions.union(
                    get_matched_versions(
                        find_all_versions(package),
                        selector,
                        exhaustive=VERIFY_EXHAUSTIVE_DEPENDENCIES,
                    )
                )

            if len(versions) == 0:
                log.error(f"Package/Version {package} not on NPM\n")
                continue

            line_match_terms = merged_original_names.get(package, set([package]))
            idx = next(
                iter(
                    [
                        ix
                        for ix, line in enumerate(raw_requirement_lines)
                        if any(term in line for term in line_match_terms)
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
                    lambda d: d.name == package,
                    dependencies,
                ),
                None,
            )
            if not dep:
                dep = Dependency(name=package, versions=set())
                dependencies.append(dep)

            dep.versions.update(dep_versions)

        return dependencies

    def scan_local(
        self,
        path: str,
        rules=None,
        callback: typing.Callable[[dict], None] = noop,
        exclude_dev: bool = False,
    ) -> Tuple[List[DependencyFile], list[dict]]:
        """
        Scans a local package.json file or directory, with optional
        exclusion of devDependencies.

        Args:
            path (str): path to package.json or directory to search
            rules: list of rules to apply
            callback: callback to call for each result
            exclude_dev (bool): when True, devDependencies are skipped.
                Only production dependencies under the "dependencies" key
                are scanned. Defaults to False.

        Returns:
            Tuple of (dependency files, scan results)
        """
        requirement_paths = []

        if os.path.isfile(path):
            requirement_paths.append(path)
        elif os.path.isdir(path):
            requirement_paths.extend(self.find_requirements(path))
        else:
            raise ValueError(f"unable to find file or directory {path}")

        dep_files: List[DependencyFile] = []

        for req in requirement_paths:
            with open(req, "r") as f:
                dep_files.append(
                    DependencyFile(
                        file_path=req,
                        dependencies=self.parse_requirements(
                            f.read(), exclude_dev=exclude_dev
                        ),
                    )
                )

        deps_to_scan = [d for d_file in dep_files for d in d_file.dependencies]
        results = self.scan_dependencies(deps_to_scan, rules, callback)

        return dep_files, results

    def find_requirements(self, directory: str) -> list[str]:
        requirement_files = []
        for root, dirs, files in os.walk(directory):
            for name in files:
                if re.match(r"^package\.json$", name, flags=re.IGNORECASE):
                    requirement_files.append(os.path.join(root, name))
        return requirement_files
