import logging

from guarddog.scanners.go_package_scanner import GoModuleScanner
from guarddog.scanners.scanner import ProjectScanner

log = logging.getLogger("guarddog")


class GoDependenciesScanner(ProjectScanner):
    def __init__(self) -> None:
        super().__init__(GoModuleScanner())

    def parse_requirements(
        self, raw_requirements: str
    ) -> dict[str, set[str]]:  # returns { package: version }
        raise NotImplementedError("TODO")
