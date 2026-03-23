from guarddog.scanners.scanner import DependencyFile
from typing import List, Optional
from guarddog.ecosystems import ECOSYSTEM


class BaseReporter:
    """
    Base class for all reporters.
    """

    @staticmethod
    def render_scan(
        scan_results: dict,
        ecosystem: Optional[ECOSYSTEM] = None,
        verbose: bool = False,
    ) -> tuple[str, str]:
        """
        Report the scans results.
        """
        raise NotImplementedError("Subclasses must implement this method.")

    @staticmethod
    def render_verify(
        dependency_files: List[DependencyFile],
        rule_names: list[str],
        scan_results: list[dict],
        ecosystem: ECOSYSTEM = None,
        verbose: bool = False,
    ) -> tuple[str, str]:
        """
        Report the scans results.
        """
        raise NotImplementedError("Subclasses must implement this method.")
