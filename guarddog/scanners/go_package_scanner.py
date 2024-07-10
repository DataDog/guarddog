import logging
from typing import Tuple

from guarddog.analyzer.analyzer import Analyzer
from guarddog.ecosystems import ECOSYSTEM
from guarddog.scanners.scanner import PackageScanner

log = logging.getLogger("guarddog")


class GoModuleScanner(PackageScanner):
    def __init__(self) -> None:
        super().__init__(Analyzer(ECOSYSTEM.GO))

    def download_and_get_package_info(
        self, directory: str, package_name: str, version=None
    ) -> Tuple[dict, str]:
        raise NotImplementedError("TODO")
