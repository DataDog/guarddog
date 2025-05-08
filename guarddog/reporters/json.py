import json
from typing import List
from guarddog.scanners.scanner import DependencyFile
from guarddog.ecosystems import ECOSYSTEM

from guarddog.reporters import BaseReporter


class JsonReporter(BaseReporter):
    @staticmethod
    def render_verify(
        dependency_files: List[DependencyFile],
        rule_names: list[str],
        scan_results: list[dict],
        ecosystem: ECOSYSTEM,
    ) -> tuple[str, str]:
        return json.dumps(scan_results), ""

    @staticmethod
    def render_scan(scan_results: dict) -> tuple[str, str]:
        """
        Report the scans results in a json format.

        Args:
            scan_results (dict): The scan results to be reported.
        """
        # this reporter will output the errors in stdout
        return json.dumps(scan_results), ""
