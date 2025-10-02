import logging
import os
import re
from dataclasses import dataclass
from typing import List

from guarddog.scanners.go_package_scanner import GoModuleScanner
from guarddog.scanners.scanner import ProjectScanner
from guarddog.scanners.scanner import Dependency, DependencyVersion

log = logging.getLogger("guarddog")


@dataclass
class GoRequirement:
    module: str
    version: str


@dataclass
class GoModule:
    module: str
    go: str
    toolchain: str
    requirements: List[GoRequirement]


class GoDependenciesScanner(ProjectScanner):
    def __init__(self) -> None:
        super().__init__(GoModuleScanner())

    def parse_requirements(self, raw_requirements: str) -> List[Dependency]:
        main_mod = self.parse_go_mod_file(raw_requirements)

        dependencies: List[Dependency] = []
        for dependency in main_mod.requirements:
            version = dependency.version
            name = dependency.module
            idx = next(
                iter(
                    [
                        ix
                        for ix, line in enumerate(raw_requirements.splitlines())
                        if name in line
                    ]
                ),
                0,
            )

            dep_versions = [DependencyVersion(version=version, location=idx + 1)]

            dep = next(
                filter(
                    lambda d: d.name == name,
                    dependencies,
                ),
                None,
            )
            if not dep:
                dep = Dependency(name=name, versions=set())
                dependencies.append(dep)

            dep.versions.update(dep_versions)
        return dependencies

    # Read https://go.dev/ref/mod#go-mod-file to learn more about the go.mod syntax
    def parse_go_mod_file(self, go_mod_content: str) -> GoModule:
        module = ""
        go = ""
        toolchain = ""
        requirements = []

        is_in_block = None
        for line in go_mod_content.splitlines():
            line = line.strip()

            if line.startswith("//"):  # Ignore comments
                continue
            elif line.startswith("module "):
                module = line.split()[1]
            elif line.startswith("go "):
                go = line.split()[1]
            elif line.startswith("toolchain "):
                toolchain = line.split()[1]
            elif line.startswith("require ("):
                is_in_block = "require"
            elif line.startswith("require "):
                parts = line.split()
                requirements.append(GoRequirement(parts[1], parts[2]))
            elif line.endswith(")") and is_in_block:
                is_in_block = None
            elif is_in_block == "require" and line != "":
                parts = line.split()
                requirements.append(GoRequirement(parts[0], parts[1]))
            # TODO: support exclude, replace and retract statements

        return GoModule(module, go, toolchain, requirements)

    def find_requirements(self, directory: str) -> list[str]:
        requirement_files = []
        for root, dirs, files in os.walk(directory):
            for name in files:
                if re.match(r"^go\.mod$", name, flags=re.IGNORECASE):
                    requirement_files.append(os.path.join(root, name))
        return requirement_files
