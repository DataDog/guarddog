import os
import re

from termcolor import colored
from guarddog.reporters import BaseReporter
from typing import List, Optional
from guarddog.scanners.scanner import DependencyFile
from guarddog.ecosystems import ECOSYSTEM
from collections import defaultdict

# C0 controls except \n (0x0a) and \t (0x09); DEL (0x7f); C1 controls (0x80-0x9f).
# Attacker-controlled values (file paths, code snippets, messages, identifiers)
# may contain these bytes; rendering them raw would let a malicious package
# inject ANSI/OSC sequences into analyst terminals or CI logs.
_TERMINAL_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _sanitize(value: object) -> str:
    return _TERMINAL_CONTROL_RE.sub(lambda m: f"\\x{ord(m.group(0)):02x}", str(value))


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
                "Some rules failed to run while scanning "
                + _sanitize(identifier)
                + ":",
                "yellow",
            )
        )
        lines.append("")
        for rule in errors:
            lines.append(f"* {_sanitize(rule)}: {_sanitize(errors[rule])}")

        return "\n".join(lines)

    # MITRE ATT&CK tactics grouped under plain-English stage labels.
    ATTACK_STAGES = {
        "Initial execution": [
            "reconnaissance",
            "resource-development",
            "initial-access",
            "execution",
        ],
        "Post-compromise behavior": [
            "persistence",
            "privilege-escalation",
            "defense-evasion",
            "credential-access",
            "discovery",
        ],
        "Exfiltration": [
            "lateral-movement",
            "collection",
            "command-and-control",
            "exfiltration",
            "impact",
        ],
    }

    LABEL_DISPLAY = {
        "no_risks_detected": "No risks detected",
        "low": "Low risk",
        "suspicious": "Suspicious",
        "malicious": "Malicious",
    }

    @staticmethod
    def _score_color(label: str) -> str | None:
        if label == "malicious":
            return "red"
        if label == "suspicious":
            return "yellow"
        return None

    @staticmethod
    def _severity_color(severity: str) -> str | None:
        if severity == "high":
            return "red"
        if severity == "medium":
            return "yellow"
        return None

    # Loudest color a finding may use, per overall band. A Low-risk package must
    # never render redder than a Suspicious one: a single high-severity rule
    # (often a low-specificity false positive) would otherwise out-shout a real
    # attack chain built from many low-severity findings.
    _BAND_CEILING = {
        "malicious": "red",
        "suspicious": "yellow",
        "low": None,
        "no_risks_detected": None,
    }

    _COLOR_RANK = {None: 0, "yellow": 1, "red": 2}

    @staticmethod
    def _clamp_color(color: str | None, ceiling: str | None) -> str | None:
        rank = HumanReadableReporter._COLOR_RANK
        return color if rank.get(color, 0) <= rank.get(ceiling, 0) else ceiling

    @staticmethod
    def _strip_prefix(path: str, prefix: Optional[str]) -> str:
        if not prefix or not path:
            return path
        loc, _, line = path.partition(":")
        try:
            rel = os.path.relpath(loc, prefix)
        except ValueError:
            return path
        if rel.startswith(".."):
            return path
        return f"{rel}:{line}" if line else rel

    @staticmethod
    def _common_path_prefix(paths: list[str]) -> Optional[str]:
        """Longest directory prefix shared by all paths; None if not stripable.

        Requires at least two paths: a single location has no "common" prefix to
        strip, and stripping it would collapse the whole path to ".".
        """
        cleaned = []
        for p in paths:
            if not p:
                continue
            cleaned.append(p.split(":", 1)[0])
        if len(cleaned) < 2:
            return None
        try:
            common = os.path.commonpath(cleaned)
        except ValueError:
            return None
        # Only strip if the common prefix is a directory (has a separator past
        # the root), otherwise we'd strip useful path components.
        if common in ("", "/", "."):
            return None
        return common

    # Context code lines: readable but subordinate to the bold matched span.
    _CODE_CONTEXT_COLOR = "light_grey"

    @staticmethod
    def _render_code_block(code, match, indent: str = "      ") -> List[str]:
        """Render a snippet with context muted and the matched span emphasized.

        Emphasis is by weight and brightness, not hue: the flagged bytes stay the
        terminal default color in bold while everything around them is muted, so
        the eye lands on the match without spending a color that means "risk".
        """
        if isinstance(code, bytes):
            code = code.decode("utf-8", errors="replace")
        snippet = _sanitize(code).rstrip()
        if not snippet:
            return []

        context = HumanReadableReporter._CODE_CONTEXT_COLOR
        needle = _sanitize(match).strip() if match else ""
        out: List[str] = []
        for line in snippet.splitlines():
            idx = line.find(needle) if needle else -1
            if idx == -1:
                out.append(indent + colored(line, context))
                continue
            out.append(
                indent
                + colored(line[:idx], context)
                + colored(needle, None, attrs=["bold"])
                + colored(line[idx + len(needle) :], context)
            )
        return out

    @staticmethod
    def _rail(lines: List[str], color: str | None) -> List[str]:
        """Prefix each line with a colored vertical rail, grouping a risk block."""
        bar = colored("│", color)
        return [f"{bar} {line}" for line in lines]

    @staticmethod
    def _format_one_risk(
        risk: dict, path_prefix: Optional[str], ceiling: str | None
    ) -> List[str]:
        """Render a single risk as a railed block: rule, desc, location, code.

        The rail carries the band color (red/yellow), or a muted grey for the Low
        band, so each finding reads as its own cell without fragile box borders.
        """
        sev_color = HumanReadableReporter._clamp_color(
            HumanReadableReporter._severity_color(risk.get("severity", "low")),
            ceiling,
        )
        rule = _sanitize(risk.get("threat_identifies", risk["threat_rule"]))
        desc = _sanitize(risk.get("threat_description", ""))
        loc_raw = risk.get("threat_location", "")
        loc = (
            HumanReadableReporter._strip_prefix(loc_raw, path_prefix)
            if loc_raw
            else _sanitize(risk["file_path"])
        )
        loc_kw = "at" if loc_raw else "in"

        block: List[str] = [
            "* " + colored(rule, sev_color, attrs=["bold"]),
        ]
        if desc:
            block.append("  " + colored(desc, sev_color))
        block.append("  " + colored(f"{loc_kw} {_sanitize(loc)}", "dark_grey"))

        code = risk.get("threat_code", "")
        if code:
            block += HumanReadableReporter._render_code_block(
                code, risk.get("threat_match"), indent="    "
            )

        cap = risk.get("capability_identifies")
        if cap:
            block.append("  " + colored(f"(enabled by {_sanitize(cap)})", "dark_grey"))

        rail_color = ceiling or "dark_grey"
        return HumanReadableReporter._rail(block, rail_color) + [""]

    @staticmethod
    def _format_findings(
        risks: list, path_prefix: Optional[str], ceiling: str | None
    ) -> List[str]:
        """Per-tactic findings list, colored by rule severity clamped to the band."""
        lines: List[str] = []
        if not risks:
            return lines

        tactics_to_risks = defaultdict(list)
        for risk in risks:
            for tactic in risk["mitre_tactics"]:
                tactics_to_risks[tactic].append(risk)

        for stage_name, stage_tactics in HumanReadableReporter.ATTACK_STAGES.items():
            if not any(tactic in tactics_to_risks for tactic in stage_tactics):
                continue

            lines.append("")
            lines.append(colored(f"── {stage_name} ──", None, attrs=["bold"]))
            lines.append("")

            for tactic in stage_tactics:
                if tactic not in tactics_to_risks:
                    continue

                tactic_risks = tactics_to_risks[tactic]
                count = len(tactic_risks)
                noun = "indicator" if count == 1 else "indicators"
                lines.append(
                    colored(f"{_sanitize(tactic)}-risk", ceiling, attrs=["bold"])
                    + f": found {count} {noun}"
                )

                for risk in tactic_risks:
                    lines += HumanReadableReporter._format_one_risk(
                        risk, path_prefix, ceiling
                    )

                lines.append("")

        return lines

    @staticmethod
    def _format_summary(risk_score: dict, num_risks: int) -> List[str]:
        score = risk_score.get("score", 0)
        label = risk_score.get("label", "no_risks_detected")
        label_display = HumanReadableReporter.LABEL_DISPLAY.get(label, label)
        score_color = HumanReadableReporter._score_color(label)

        score_line = (
            colored(f"{score}/10", score_color, attrs=["bold"])
            + " "
            + colored(label_display, score_color, attrs=["bold"])
        )
        noun = "risk" if num_risks == 1 else "risks"
        stats = f"{num_risks} {noun} detected"

        return [
            "",
            colored("─" * 40, "dark_grey"),
            f"Risk score:  {score_line}",
            colored(stats, "dark_grey"),
        ]

    @staticmethod
    def _format_header(identifier: str, num_risks: int) -> List[str]:
        bold = colored(_sanitize(identifier), None, attrs=["bold"])
        if num_risks == 0:
            return [f"No risks found in {bold}", ""]
        noun = "risk" if num_risks == 1 else "risks"
        return [f"Scanning {bold}, found {num_risks} {noun}.", ""]

    @staticmethod
    def _collect_locations(risks: list) -> list[str]:
        return [r["threat_location"] for r in risks if r.get("threat_location")]

    @staticmethod
    def print_scan_results(identifier: str, results: dict) -> str:
        risk_score = results.get("risk_score")
        risks = results.get("risks", [])

        path_prefix = HumanReadableReporter._common_path_prefix(
            HumanReadableReporter._collect_locations(risks)
        )

        label = (
            risk_score.get("label", "no_risks_detected")
            if risk_score
            else "no_risks_detected"
        )
        ceiling = HumanReadableReporter._BAND_CEILING.get(label)

        lines: List[str] = []
        lines += HumanReadableReporter._format_header(identifier, len(risks))
        if risks:
            lines += HumanReadableReporter._format_findings(risks, path_prefix, ceiling)
        if risk_score:
            lines += HumanReadableReporter._format_summary(risk_score, len(risks))

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
