from guarddog.scanners.scanner import DependencyFile
from typing import List
from guarddog.ecosystems import ECOSYSTEM


class BaseReporter:
    """
    Base class for all reporters.
    """

    @staticmethod
    def render_scan(scan_results: dict) -> tuple[str, str]:
        """
        Report the scans results.
        """
        raise NotImplementedError("Subclasses must implement this method.")

    @staticmethod
    def render_verify(
        dependency_files: List[DependencyFile],
        rule_names: list[str],
        scan_results: list[dict],
        ecosystem: ECOSYSTEM,
    ) -> tuple[str, str]:
        """
        Report the scans results.
        """
        raise NotImplementedError("Subclasses must implement this method.")
