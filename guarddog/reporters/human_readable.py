from termcolor import colored
from guarddog.reporters import BaseReporter
from typing import List
from guarddog.scanners.scanner import DependencyFile
from guarddog.ecosystems import ECOSYSTEM
from collections import defaultdict


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
    def _format_risk_score(risk_score: dict, risks: list, num_issues: int) -> List[str]:
        """Format risk score information for display"""
        lines = []

        score = risk_score.get("score", 0)
        label = risk_score.get("label", "none")

        # MITRE ATT&CK tactics grouped by attack stage
        ATTACK_STAGES = {
            "EARLY STAGE": [
                "reconnaissance",
                "resource-development",
                "initial-access",
                "execution",
            ],
            "MID STAGE": [
                "persistence",
                "privilege-escalation",
                "defense-evasion",
                "credential-access",
                "discovery",
            ],
            "LATE STAGE": [
                "lateral-movement",
                "collection",
                "command-and-control",
                "exfiltration",
                "impact",
            ],
        }

        # Color-code the score
        if label == "high":
            score_color = "red"
        elif label == "medium":
            score_color = "yellow"
        else:
            score_color = "green"

        lines.append("")
        lines.append(colored("═" * 70, "cyan"))
        lines.append(colored("SUMMARY", "cyan", attrs=["bold"]))
        lines.append("")
        lines.append(
            colored("Risk Score: ", None, attrs=["bold"])
            + colored(f"{score}/10", score_color, attrs=["bold"])
            + colored(f" ({label.upper()})", score_color, attrs=["bold"])
        )
        lines.append(colored(f"Total Indicators: {num_issues}", None, attrs=["bold"]))
        lines.append(colored(f"Risks Formed: {len(risks)}", None, attrs=["bold"]))

        if risks:
            lines.append("")
            lines.append(colored("═" * 70, "cyan"))

            # Group risks by MITRE tactic
            tactics_to_risks = defaultdict(list)
            for risk in risks:
                for tactic in risk["mitre_tactics"]:
                    tactics_to_risks[tactic].append(risk)

            # Display each stage with its tactics
            for stage_name, stage_tactics in ATTACK_STAGES.items():
                # Check if this stage has any risks
                stage_has_risks = any(
                    tactic in tactics_to_risks for tactic in stage_tactics
                )
                if not stage_has_risks:
                    continue

                # Stage header with arrow
                lines.append("")
                lines.append(colored(f"-> {stage_name}", "cyan", attrs=["bold"]))
                lines.append("")

                # Display each tactic in this stage
                for tactic in stage_tactics:
                    if tactic not in tactics_to_risks:
                        continue

                    tactic_risks = tactics_to_risks[tactic]
                    lines.append(
                        colored(f"{tactic}-risk", "red", attrs=["bold"])
                        + f": Found {len(tactic_risks)} issue(s)"
                    )

                    for risk in tactic_risks:
                        # Show threat identifies (hierarchical name) and description
                        threat_identifies = risk.get(
                            "threat_identifies", risk["threat_rule"]
                        )
                        threat_desc = risk.get("threat_description", "")
                        threat_loc = risk.get("threat_location", "")
                        threat_code = risk.get("threat_code", "")

                        # Format location
                        location_str = (
                            f" at {threat_loc}"
                            if threat_loc
                            else f" in {risk['file_path']}"
                        )

                        lines.append(
                            f"  * {colored(threat_identifies, None, attrs=['bold'])}: "
                            f"{threat_desc}{location_str}"
                        )

                        # Show matched code if available
                        if threat_code:
                            code_display = threat_code.strip()
                            if isinstance(code_display, bytes):
                                code_display = code_display.decode(
                                    "utf-8", errors="replace"
                                )
                            lines.append(
                                f"     {colored(code_display, None, 'on_red', attrs=['bold'])}"
                            )

                        # Optionally show capability identifies
                        cap_identifies = risk.get("capability_identifies")
                        if cap_identifies:
                            lines.append(
                                f"    (enabled by {colored(cap_identifies, 'yellow')})"
                            )

                    lines.append("")  # Space between tactics

        return lines

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

        # Always show risk score
        risk_score = results.get("risk_score")
        risks = results.get("risks", [])
        has_risks = bool(risks)

        if risk_score:
            lines.extend(
                HumanReadableReporter._format_risk_score(risk_score, risks, num_issues)
            )

        # Show other indicators (findings that didn't form risks)
        findings = results.get("results", {})

        # Track which rules were used in risks
        rules_in_risks = set()
        if has_risks:
            for risk in risks:
                rules_in_risks.add(risk["threat_rule"])
                if risk.get("capability_rule"):
                    rules_in_risks.add(risk["capability_rule"])

        # Filter findings that weren't part of risks
        other_findings = {
            rule_name: matches
            for rule_name, matches in findings.items()
            if rule_name not in rules_in_risks and matches
        }

        if other_findings:
            lines.append("")
            lines.append(colored("═" * 70, "cyan"))
            lines.append(colored("OTHER INDICATORS", "cyan", attrs=["bold"]))
            lines.append("")

            for rule_name in other_findings:
                description = other_findings[rule_name]
                if isinstance(description, str):  # package metadata
                    lines.append(
                        colored(rule_name, None, attrs=["bold"]) + ": " + description
                    )
                    lines.append("")
                elif isinstance(description, list):  # semgrep/yara rule result:
                    source_code_findings = description
                    lines.append(
                        colored(rule_name, None, attrs=["bold"])
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

            lines.append(colored("═" * 70, "cyan"))
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
