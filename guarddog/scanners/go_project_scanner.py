import logging
from dataclasses import dataclass
from typing import List

from guarddog.scanners.go_package_scanner import GoModuleScanner
from guarddog.scanners.scanner import ProjectScanner

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

    def parse_requirements(self, raw_requirements: str) -> dict[str, set[str]]:
        main_mod = self.parse_go_mod_file(raw_requirements)

        return {
            requirement.module: set([requirement.version])
            for requirement in main_mod.requirements
        }

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
