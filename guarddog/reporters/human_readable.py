from termcolor import colored
from guarddog.reporters import BaseReporter
from typing import List
from guarddog.scanners.scanner import DependencyFile
from guarddog.ecosystems import ECOSYSTEM


class HumanReadableReporter(BaseReporter):
    """
    HumanReadableReporter is a class that formats and prints scan results in a human-readable format.
    """

    @staticmethod
    def print_errors(identifier: str, results: dict) -> str:
        errors = results.get("errors", [])
        if not errors:
            return ""

        lines = []
        lines.append("")
        lines.append(
            colored(
                "Some rules failed to run while scanning " + identifier + ":",
                "yellow",
            )
        )
        lines.append("")
        for rule in errors:
            lines.append(f"* {rule}: {errors[rule]}")

        return "\n".join(lines)

    @staticmethod
    def print_scan_results(identifier: str, results: dict) -> str:

        def _format_code_line_for_output(code) -> str:
            return "    " + colored(
                code.strip().replace("\n", "\n    ").replace("\t", "  "),
                None,
                "on_red",
                attrs=["bold"],
            )

        num_issues = results.get("issues")
        lines = []

        if num_issues == 0:
            lines.append(
                "Found "
                + colored("0 potentially malicious indicators", "green", attrs=["bold"])
                + " scanning "
                + colored(identifier, None, attrs=["bold"])
            )
            lines.append("")
        else:
            lines.append(
                "Found "
                + colored(
                    str(num_issues) + " potentially malicious indicators",
                    "red",
                    attrs=["bold"],
                )
                + " in "
                + colored(identifier, None, attrs=["bold"])
            )
            lines.append("")

            findings = results.get("results", [])
            for finding in findings:
                description = findings[finding]
                if isinstance(description, str):  # package metadata
                    lines.append(
                        colored(finding, None, attrs=["bold"]) + ": " + description
                    )
                    lines.append("")
                elif isinstance(description, list):  # semgrep rule result:
                    source_code_findings = description
                    lines.append(
                        colored(finding, None, attrs=["bold"])
                        + ": found "
                        + str(len(source_code_findings))
                        + " source code matches"
                    )
                    for finding in source_code_findings:
                        lines.append(
                            "  * "
                            + finding["message"]
                            + " at "
                            + finding["location"]
                            + "\n    "
                            + _format_code_line_for_output(finding["code"])
                        )
                    lines.append("")

        return "\n".join(lines)

    @staticmethod
    def render_scan(scan_results: dict) -> tuple[str, str]:
        """
        Report the scans results in a human-readable format.

        Args:
            scan_results (dict): The scan results to be reported.
        """
        return (
            HumanReadableReporter.print_scan_results(
                identifier=scan_results["package"], results=scan_results
            ),
            HumanReadableReporter.print_errors(
                identifier=scan_results["package"], results=scan_results
            ),
        )

    @staticmethod
    def render_verify(
        dependency_files: List[DependencyFile],
        rule_names: list[str],
        scan_results: list[dict],
        ecosystem: ECOSYSTEM,
    ) -> tuple[str, str]:
        return (
            "\n".join(
                [
                    HumanReadableReporter.print_scan_results(
                        identifier=s["dependency"], results=s["result"]
                    )
                    for s in scan_results
                ]
            ),
            "\n".join(
                [
                    HumanReadableReporter.print_errors(
                        identifier=s["dependency"], results=s["result"]
                    )
                    for s in scan_results
                ]
            ),
        )
