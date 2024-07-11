import logging
import requests

from guarddog.scanners.go_package_scanner import (
    GoModuleScanner,
    GOPROXY_URL,
    escape_package_name,
)
from guarddog.scanners.scanner import ProjectScanner

log = logging.getLogger("guarddog")


class GoModule:
    def __init__(self):
        self.module = ""
        self.go = ""
        self.toolchain = ""
        self.requirements = []


class Requirement:
    def __init__(self, module: str, version: str):
        self.module = module
        self.version = version


class GoDependenciesScanner(ProjectScanner):
    def __init__(self) -> None:
        super().__init__(GoModuleScanner())

    def parse_requirements(self, raw_requirements: str) -> dict[str, set[str]]:
        main_mod = self.parse_go_mod_file(raw_requirements)
        # TODO: implement the Minimal Version Selection algorithm as described
        # In https://research.swtch.com/vgo-mvs and https://go.dev/ref/mod#minimal-version-selection

        return {
            requirement.module: set([requirement.version])
            for requirement in main_mod.requirements
        }

    # Read https://go.dev/ref/mod#go-mod-file to learn more about the go.mod syntax
    def parse_go_mod_file(self, go_mod_content: str) -> GoModule:
        go_module = GoModule()

        is_in_block = None
        for line in go_mod_content.splitlines():
            line = line.strip()

            if line.startswith("//"):  # Ignore comments
                continue
            elif line.startswith("module "):
                go_module.module = line.split()[1]
            elif line.startswith("go "):
                go_module.go = line.split()[1]
            elif line.startswith("toolchain "):
                go_module.toolchain = line.split()[1]
            elif line.startswith("require ("):
                is_in_block = "require"
            elif line.startswith("require "):
                parts = line.split()
                go_module.requirements.append(Requirement(parts[1], parts[2]))
            elif line.endswith(")") and is_in_block:
                is_in_block = None
            elif is_in_block == "require" and line != "":
                parts = line.split()
                go_module.requirements.append(Requirement(parts[0], parts[1]))
            # TODO: support exclude, replace and retract statements

        return go_module

    def get_go_mod_file(self, package_name: str, version: str) -> GoModule:
        go_mod_file_url = (
            f"{GOPROXY_URL}/{escape_package_name(package_name)}/@v/{version}.mod"
        )
        response = requests.get(go_mod_file_url)
        response.raise_for_status()
        return self.parse_go_mod_file(response.text)
