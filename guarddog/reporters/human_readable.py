from termcolor import colored
from typing import Generator
from guarddog.reporters import BaseReporter
from typing import List
from guarddog.scanners.scanner import DependencyFile
from guarddog.ecosystems import ECOSYSTEM


class HumanReadableReporter(BaseReporter):
    """
    HumanReadableReporter is a class that formats and prints scan results in a human-readable format.
    """

    @staticmethod
    def print_errors(identifier: str, results: dict) -> Generator:
        errors = results.get("errors", [])
        if not errors:
            return
        yield ("")
        yield (
            colored(
                "Some rules failed to run while scanning " + identifier + ":",
                "yellow",
            )
        )
        yield ("")
        for rule in errors:
            yield (f"* {rule}: {errors[rule]}")

    @staticmethod
    def print_scan_results(identifier: str, results: dict) -> Generator:

        def _format_code_line_for_output(code) -> str:
            return "    " + colored(
                code.strip().replace("\n", "\n    ").replace("\t", "  "),
                None,
                "on_red",
                attrs=["bold"],
            )

        num_issues = results.get("issues")

        if num_issues == 0:
            yield (
                "Found "
                + colored("0 potentially malicious indicators", "green", attrs=["bold"])
                + " scanning "
                + colored(identifier, None, attrs=["bold"])
            )
            yield ("")
        else:
            yield (
                "Found "
                + colored(
                    str(num_issues) + " potentially malicious indicators",
                    "red",
                    attrs=["bold"],
                )
                + " in "
                + colored(identifier, None, attrs=["bold"])
            )
            yield ("")

            findings = results.get("results", [])
            for finding in findings:
                description = findings[finding]
                if isinstance(description, str):  # package metadata
                    yield (colored(finding, None, attrs=["bold"]) + ": " + description)
                    yield ("")
                elif isinstance(description, list):  # semgrep rule result:
                    source_code_findings = description
                    yield (
                        colored(finding, None, attrs=["bold"])
                        + ": found "
                        + str(len(source_code_findings))
                        + " source code matches"
                    )
                    for finding in source_code_findings:
                        yield (
                            "  * "
                            + finding["message"]
                            + " at "
                            + finding["location"]
                            + "\n    "
                            + _format_code_line_for_output(finding["code"])
                        )
                    yield ("")

    @staticmethod
    def render_scan(scan_results: dict) -> tuple[str, str]:
        """
        Report the scans results in a human-readable format.

        Args:
            scan_results (dict): The scan results to be reported.
        """
        return (
            "\n".join(
                HumanReadableReporter.print_scan_results(
                    identifier=scan_results["package"], results=scan_results
                )
            ),
            "\n".join(
                HumanReadableReporter.print_errors(
                    identifier=scan_results["package"], results=scan_results
                )
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
                map(
                    lambda s: "\n".join(
                        HumanReadableReporter.print_scan_results(
                            identifier=s["dependency"], results=s["result"]
                        ),
                    ),
                    scan_results,
                )
            ),
            "\n".join(
                map(
                    lambda s: "\n".join(
                        HumanReadableReporter.print_errors(
                            identifier=s["dependency"], results=s["result"]
                        ),
                    ),
                    scan_results,
                )
            ),
        )
