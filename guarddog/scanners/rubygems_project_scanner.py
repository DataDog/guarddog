import logging
import os
import re
from typing import List

from guarddog.scanners.rubygems_package_scanner import RubyGemsPackageScanner
from guarddog.scanners.scanner import ProjectScanner, Dependency, DependencyVersion

log = logging.getLogger("guarddog")


class RubyGemsRequirementsScanner(ProjectScanner):
    """
    Scans all gems in the Gemfile.lock file of a project
    """

    def __init__(self) -> None:
        super().__init__(RubyGemsPackageScanner())

    def parse_requirements(self, raw_requirements: str) -> List[Dependency]:
        """
        Parses Gemfile.lock and extracts gem names and versions.

        Gemfile.lock format:
        GEM
          remote: https://rubygems.org/
          specs:
            actioncable (7.0.4)
              actionpack (= 7.0.4)
            rails (7.0.4)
              ...
        """
        dependencies: List[Dependency] = []
        lines = raw_requirements.splitlines()

        in_gem_specs = False
        gem_pattern = re.compile(r"^    (\S+) \(([^)]+)\)$")

        for idx, line in enumerate(lines):
            if line.strip() == "GEM":
                continue
            elif line.strip() == "specs:":
                in_gem_specs = True
                continue
            elif line and not line.startswith(" "):
                in_gem_specs = False
                continue

            if not in_gem_specs:
                continue

            match = gem_pattern.match(line)
            if match:
                name = match.group(1)
                version = match.group(2)

                dep = next(
                    filter(lambda d: d.name == name, dependencies),
                    None,
                )
                if not dep:
                    dep = Dependency(name=name, versions=set())
                    dependencies.append(dep)

                dep.versions.add(
                    DependencyVersion(version=version, location=idx + 1)
                )

        return dependencies

    def find_requirements(self, directory: str) -> list[str]:
        requirement_files = []
        for root, dirs, files in os.walk(directory):
            for name in files:
                if name == "Gemfile.lock":
                    requirement_files.append(os.path.join(root, name))
        return requirement_files
