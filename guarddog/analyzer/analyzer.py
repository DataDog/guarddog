import logging
import os
import yara  # type: ignore

from collections import defaultdict
from fnmatch import fnmatch
from pathlib import Path
from typing import Optional, Dict, List

from guarddog.analyzer.metadata import get_metadata_detectors
from guarddog.analyzer.sourcecode import get_sourcecode_rules, YaraRule
from guarddog.analyzer.risk_engine import (
    Finding,
    Level,
    form_risks_from_findings,
    calculate_risk_score,
    validate_identifies,
    validate_mitre_tactics,
)
from guarddog.utils.config import YARA_EXT_EXCLUDE
from guarddog.ecosystems import ECOSYSTEM, LANGUAGE

SOURCECODE_RULES_PATH = os.path.join(os.path.dirname(__file__), "sourcecode")
log = logging.getLogger("guarddog")


class Analyzer:
    """
    Analyzes a local directory for threats found by source code or metadata rules

    Attributes:
        ecosystem (str): name of the current ecosystem
        metadata_ruleset (list): list of metadata rule names
        sourcecode_ruleset (list): list of source code rule names
        ioc_ruleset (list): list of ioc rule names

        exclude (list): list of directories to exclude from source code search

        metadata_detectors(list): list of metadata detectors
    """

    def __init__(self, ecosystem=ECOSYSTEM.PYPI) -> None:
        self.ecosystem = ecosystem

        # Rules and associated detectors
        self.metadata_detectors = get_metadata_detectors(ecosystem)

        self.metadata_ruleset: set[str] = set(self.metadata_detectors.keys())
        self.yara_ruleset: set[str] = set(
            r.id for r in get_sourcecode_rules(ecosystem, YaraRule)
        )

        # Define paths to exclude from sourcecode analysis
        self.exclude = [
            "helm",
            ".idea",
            "venv",
            "test",
            "tests",
            ".env",
            "dist",
            "build",
            "migrations",
            ".github",
        ]

    # Comment filtering helpers

    @staticmethod
    def _detect_language(file_path: str) -> Optional[LANGUAGE]:
        """Detect programming language based on file extension."""
        ext = Path(file_path).suffix.lower()
        language_map = {
            ".py": LANGUAGE.PYTHON,
            ".pyx": LANGUAGE.PYTHON,
            ".pyi": LANGUAGE.PYTHON,
            ".js": LANGUAGE.JAVASCRIPT,
            ".jsx": LANGUAGE.JAVASCRIPT,
            ".mjs": LANGUAGE.JAVASCRIPT,
            ".cjs": LANGUAGE.JAVASCRIPT,
            ".ts": LANGUAGE.TYPESCRIPT,
            ".tsx": LANGUAGE.TYPESCRIPT,
            ".go": LANGUAGE.GO,
            ".rb": LANGUAGE.RUBY,
        }
        return language_map.get(ext)

    @staticmethod
    def _is_in_multiline_comment(
        file_path: str,
        language: LANGUAGE,
        byte_offset: Optional[int] = None,
        line_number: Optional[int] = None,
        context_window: int = 4096,
    ) -> bool:
        """
        Check if a position is within a multi-line comment block.
        Searches backwards in a limited window to find the first comment marker.

        Args:
            file_path: Path to the file
            language: Programming language
            byte_offset: Optional byte offset - if not provided, calculated from line_number
            line_number: Optional line number - used to calculate byte_offset if not provided
            context_window: Number of bytes to read before the match (default 4KB)
        """
        try:
            # Calculate byte offset from line number if not provided
            if byte_offset is None:
                if line_number is None:
                    return False
                with open(file_path, "r", errors="ignore") as f:
                    lines_before = [next(f) for _ in range(line_number - 1)]
                    byte_offset = sum(
                        len(line.encode("utf-8")) for line in lines_before
                    )

            # Read only a window of context before the match
            start_pos = max(0, byte_offset - context_window)
            with open(file_path, "rb") as f:
                f.seek(start_pos)
                window = f.read(byte_offset - start_pos).decode(
                    "utf-8", errors="ignore"
                )

            if language in [LANGUAGE.JAVASCRIPT, LANGUAGE.TYPESCRIPT, LANGUAGE.GO]:
                # Search backwards for first /* or */
                last_open = window.rfind("/*")
                last_close = window.rfind("*/")

                # If we find an opening comment and it comes after the last closing,
                # then we're inside a comment
                if last_open > last_close:
                    return True

            elif language == LANGUAGE.PYTHON:
                # For Python, check if we're inside """ or '''
                for quote in ['"""', "'''"]:
                    # Count occurrences - if odd, we're inside a docstring
                    count = window.count(quote)
                    if count % 2 == 1:
                        return True

        except Exception:
            pass

        return False

    @staticmethod
    def is_match_in_comment(
        file_path: str,
        line_number: int,
        byte_offset: Optional[int] = None,
        line_content: Optional[str] = None,
    ) -> bool:
        """
        Check if a match at a given line is within a comment.

        Args:
            file_path: Path to the file
            line_number: Line number (1-indexed) of the match
            byte_offset: Optional byte offset for multi-line comment detection optimization
            line_content: Optional pre-extracted line content to avoid re-reading file

        Returns:
            True if the match is in a comment, False otherwise
        """
        language = Analyzer._detect_language(file_path)
        if not language:
            return False

        try:
            # Get line content if not provided
            if line_content is None:
                with open(file_path, "r", errors="ignore") as f:
                    for current_line_num, line in enumerate(f, start=1):
                        if current_line_num == line_number:
                            line_content = line
                            break
                        if current_line_num > line_number:
                            return False

            if line_content is None:
                return False

            # Check single-line comments
            line_stripped = line_content.strip()
            if language in [
                LANGUAGE.PYTHON,
                LANGUAGE.RUBY,
            ] and line_stripped.startswith("#"):
                return True
            if language in [
                LANGUAGE.JAVASCRIPT,
                LANGUAGE.TYPESCRIPT,
                LANGUAGE.GO,
            ] and line_stripped.startswith("//"):
                return True

            # Check multi-line comments (byte_offset will be calculated inside if needed)
            return Analyzer._is_in_multiline_comment(
                file_path, language, byte_offset=byte_offset, line_number=line_number
            )

        except Exception:
            pass

        return False

    @staticmethod
    def format_risks(risk_objects: list, sourcecode_results: Optional[dict]) -> list:
        """Format Risk objects into the dicts consumed by reporters.

        Re-joins the exact matched bytes (`threat_match`) from the raw sourcecode
        findings by (rule, location), since the risk engine drops that detail and
        the reporter uses it to emphasize the flagged span within the snippet.
        """
        matches_by_rule_location: Dict[tuple, str] = {}
        for rule_name, rule_matches in (
            (sourcecode_results or {}).get("results", {}).items()
        ):
            if not isinstance(rule_matches, list):
                continue
            for match in rule_matches:
                if isinstance(match, dict) and match.get("location"):
                    matches_by_rule_location[(rule_name, match["location"])] = (
                        match.get("match", "")
                    )

        return [
            {
                "name": risk.name,
                "category": risk.category,
                "severity": risk.severity.value,
                "mitre_tactics": risk.mitre_tactics,
                "threat_identifies": risk.threat_finding.identifies,
                "threat_rule": risk.threat_finding.rule_name,
                "threat_description": risk.threat_finding.message or "",
                "threat_location": risk.threat_finding.location or "",
                "threat_code": risk.threat_finding.code_snippet or "",
                "threat_match": matches_by_rule_location.get(
                    (risk.threat_finding.rule_name, risk.threat_finding.location or ""),
                    "",
                ),
                "capability_identifies": (
                    risk.capability_finding.identifies
                    if risk.capability_finding
                    else None
                ),
                "capability_rule": (
                    risk.capability_finding.rule_name
                    if risk.capability_finding
                    else None
                ),
                "file_path": risk.threat_finding.file_path,
            }
            for risk in risk_objects
        ]

    def analyze(
        self,
        path,
        info=None,
        rules=None,
        name: Optional[str] = None,
        version: Optional[str] = None,
    ) -> dict:
        """
        Analyzes a package in the given path

        Args:
            path (str): path to package
            info (dict, optional): Any package information to analyze metadata. Defaults to None.
            rules (set, optional): Set of rules to analyze. Defaults to all rules.

        Raises:
            Exception: "{rule} is not a valid rule."

        Returns:
            dict[str]: map from each rule and their corresponding output, including risk score
        """

        metadata_results = None
        sourcecode_results = None

        # populate results, errors, and number of issues
        metadata_results = self.analyze_metadata(path, info, rules, name, version)
        sourcecode_results = self.analyze_sourcecode(path, rules)

        # Concatenate dictionaries together
        issues = metadata_results["issues"] + sourcecode_results["issues"]
        results = metadata_results["results"] | sourcecode_results["results"]
        errors = metadata_results["errors"] | sourcecode_results["errors"]

        # Calculate risk-based score (sourcecode + metadata)
        risk_score = self.calculate_package_risk_score(
            sourcecode_results, metadata_results
        )

        # Extract and format risks for top-level output
        risk_objects = risk_score.pop("_risks", [])
        formatted_risks = self.format_risks(risk_objects, sourcecode_results)

        return {
            "issues": issues,
            "errors": errors,
            "results": results,
            "path": path,
            "risk_score": risk_score,
            "risks": formatted_risks,  # Top-level only, not inside risk_score
        }

    def analyze_metadata(
        self,
        path: str,
        info,
        rules=None,
        name: Optional[str] = None,
        version: Optional[str] = None,
    ) -> dict:
        """
        Analyzes the metadata of a given package

        Args:
            path (str): path to package
            info (dict): package information given by PyPI Json API
            rules (set, optional): Set of metadata rules to analyze. Defaults to all rules.

        Returns:
            dict[str]: map from each metadata rule and their corresponding output
        """

        log.debug(f"Running metadata rules against package '{name}'")

        all_rules = self.metadata_ruleset
        if rules is not None:
            # filtering the full ruleset witht the user's input
            all_rules = self.metadata_ruleset & rules

        # for each metadata rule, is expected to have an nulleable string as result
        # None value represents that the rule was not matched
        results: dict[str, Optional[str]] = {}
        errors = {}
        issues = 0

        for rule in all_rules:
            try:
                log.debug(f"Running rule {rule} against package '{name}'")
                rule_matches, message = self.metadata_detectors[rule].detect(
                    info, path, name, version
                )
                results[rule] = None
                if rule_matches:
                    issues += 1
                    results[rule] = message
            except Exception as e:
                errors[rule] = f"failed to run rule {rule}: {str(e)}"

        return {"results": results, "errors": errors, "issues": issues}

    def analyze_sourcecode(self, path, rules=None) -> dict:
        """
        Analyzes the source code of a given package

        Args:
            path (str): path to directory of package
            rules (set, optional): Set of source code rules to analyze. Defaults to all rules.

        Returns:
            dict[str]: map from each source code rule and their corresponding output
        """
        return self.analyze_yara(path, rules)

    def analyze_yara(self, path: str, rules: Optional[set] = None) -> dict:
        """
        Analyzes the IOCs of a given package

        Args:
            path (str): path to package
            rules (set, optional): Set of IOC rules to analyze. Defaults to all rules.

        Returns:
            dict[str]: map from each IOC rule and their corresponding output
        """
        log.debug(f"Running yara rules against directory '{path}'")

        all_rules = self.yara_ruleset
        if rules is not None:
            # filtering the full ruleset witht the user's input
            all_rules = self.yara_ruleset & rules

        results = {rule: {} for rule in all_rules}  # type: dict
        errors: Dict[str, str] = {}
        issues = 0

        rule_results: defaultdict[str, list[dict]] = defaultdict(list)

        rules_path = {
            rule_name: os.path.join(SOURCECODE_RULES_PATH, f"{rule_name}.yar")
            for rule_name in all_rules
        }

        if len(rules_path) == 0:
            log.debug("No yara rules to run")
            return {"results": results, "errors": errors, "issues": issues}

        import time

        # Get rule metadata to access max_hits
        yara_rules = {r.id: r for r in get_sourcecode_rules(self.ecosystem, YaraRule)}

        # Run each rule separately to enable per-rule timing and max_hits optimization
        for rule_name, rule_path in rules_path.items():
            try:
                log.debug(f"Executing rule {rule_name}.yar")
                start_time = time.time()

                scan_rule = yara.compile(filepath=rule_path)

                # Get rule metadata
                rule_obj = yara_rules.get(rule_name)
                max_hits = (
                    rule_obj.max_hits
                    if rule_obj and hasattr(rule_obj, "max_hits")
                    else None
                )
                path_include = (
                    rule_obj.path_include
                    if rule_obj and hasattr(rule_obj, "path_include")
                    else None
                )
                path_exclude = (
                    rule_obj.path_exclude
                    if rule_obj and hasattr(rule_obj, "path_exclude")
                    else None
                )

                hits_found = 0
                should_stop = False

                for root, _, files in os.walk(path):
                    if should_stop:
                        break

                    for f in files:
                        if should_stop:
                            break

                        scan_file_target_abspath = os.path.join(root, f)
                        scan_file_target_relpath = os.path.relpath(
                            scan_file_target_abspath, path
                        )

                        # Check path_include patterns if specified (takes precedence)
                        if path_include:
                            patterns = [p.strip() for p in path_include.split(",")]
                            matches_pattern = any(
                                fnmatch(scan_file_target_relpath, pattern)
                                for pattern in patterns
                            )
                            if not matches_pattern:
                                continue
                        else:
                            # Default: Skip files with excluded extensions
                            if f.lower().endswith(tuple(YARA_EXT_EXCLUDE)):
                                continue

                        # Check path_exclude patterns
                        if path_exclude:
                            exclude_patterns = [
                                p.strip() for p in path_exclude.split(",")
                            ]
                            if any(
                                fnmatch(scan_file_target_relpath, pat)
                                or fnmatch(f, pat)
                                for pat in exclude_patterns
                            ):
                                continue

                        matches = scan_rule.match(scan_file_target_abspath)

                        for m in matches:

                            for s in m.strings:
                                for i in s.instances:
                                    # Convert byte offset to line number for better readability
                                    line_number = self.get_line_number_from_offset(
                                        scan_file_target_abspath, i.offset
                                    )

                                    # Filter out matches in comments
                                    if self.is_match_in_comment(
                                        scan_file_target_abspath,
                                        line_number=line_number,
                                        byte_offset=i.offset,
                                    ):
                                        log.debug(
                                            f"Filtered match in comment at {scan_file_target_relpath}:{line_number}"
                                        )
                                        continue

                                    # Extract a small window of code around the match offset
                                    # for better readability in the report.
                                    line_of_code = self.get_lines_around_offset(
                                        scan_file_target_abspath,
                                        i.offset,
                                        before=1,
                                        after=2,
                                    )

                                    # The exact bytes YARA matched, so the reporter can
                                    # emphasize the flagged span within the snippet.
                                    matched_text = ""
                                    try:
                                        if isinstance(i.matched_data, bytes):
                                            matched_text = i.matched_data.decode(
                                                "utf-8", errors="replace"
                                            )
                                    except Exception:
                                        matched_text = ""

                                    finding = {
                                        "location": f"{scan_file_target_relpath}:{line_number}",
                                        "code": self.trim_code_snippet(
                                            line_of_code, matched_text
                                        ),
                                        "match": matched_text,
                                        "message": m.meta.get(
                                            "description", f"{m.rule} rule matched"
                                        ),
                                    }

                                    # since yara can match the multiple times in the same file
                                    # leading to finding several times the same word or pattern
                                    # this dedup the matches
                                    if [
                                        f
                                        for f in rule_results[rule_name]
                                        if finding["code"] == f["code"]
                                    ]:
                                        continue

                                    issues += len(m.strings)
                                    rule_results[rule_name].append(finding)
                                    hits_found += 1

                                    # Check if we've reached max_hits
                                    if max_hits is not None and hits_found >= max_hits:
                                        should_stop = True
                                        log.debug(
                                            f"Rule {rule_name}.yar reached max_hits={max_hits}, stopping scan"
                                        )
                                        break

                                if should_stop:
                                    break

                            if should_stop:
                                break

                elapsed_time = time.time() - start_time
                log.debug(
                    f"Rule {rule_name}.yar finished, took {elapsed_time:.2f}s ({hits_found} hits found)"
                )

            except Exception as e:
                errors[rule_name] = f"failed to run rule: {str(e)}"
                log.warning(f"Rule {rule_name}.yar failed: {str(e)}")

        return {"results": results | rule_results, "errors": errors, "issues": issues}

    def get_snippet(self, file_path: str, start_line: int, end_line: int) -> str:
        """
        Returns the code snippet between start_line and stop_line in a file

        Args:
            path (str): path to file
            start_line (int): starting line number
            end_line (int): ending line number

        Returns:
            str: code snippet
        """
        snippet = []
        try:
            with open(file_path, "r") as file:
                for current_line_number, line in enumerate(file, start=1):
                    if start_line <= current_line_number <= end_line:
                        snippet.append(line)
                    elif current_line_number > end_line:
                        break
        except FileNotFoundError:
            log.error(f"File not found: {file_path}")
        except Exception as e:
            log.error(f"Error reading file {file_path}: {str(e)}")

        return "".join(snippet)

    # Makes sure the matching code to be displayed isn't too long. When the
    # matched bytes are known, the kept window is centered on them so the
    # flagged span survives truncation and the reporter can still highlight it
    # (otherwise a match buried in a long minified line gets elided away).
    def trim_code_snippet(self, code: str, match: str = "") -> str:
        THRESHOLD = 250
        if len(code) <= THRESHOLD:
            return code

        ellipsis = "..."
        match_start = code.find(match) if match else -1
        if match_start == -1:
            head = code[: THRESHOLD - len(ellipsis) - 10]
            return head + ellipsis + code[-10:]

        match_end = match_start + len(match)
        pad = max(THRESHOLD - len(match), 0) // 2
        window_start = max(match_start - pad, 0)
        window_end = min(match_end + pad, len(code))
        prefix = ellipsis if window_start > 0 else ""
        suffix = ellipsis if window_end < len(code) else ""
        return prefix + code[window_start:window_end] + suffix

    def get_line_number_from_offset(self, file_path: str, offset: int) -> int:
        """
        Convert a byte offset to a line number in a file

        Args:
            file_path: Path to the file
            offset: Byte offset in the file

        Returns:
            Line number (1-indexed) at the given offset
        """
        try:
            with open(file_path, "rb") as f:
                content = f.read(offset)

            # Count newlines up to the offset
            line_number = content.count(b"\n") + 1
            return line_number
        except Exception as e:
            log.debug(
                f"Failed to get line number at offset {offset} from {file_path}: {e}"
            )
            return offset  # Fallback to offset if conversion fails

    def get_line_at_offset(self, file_path: str, offset: int) -> str:
        """
        Extract the line of code at a given byte offset in a file

        Args:
            file_path: Path to the file
            offset: Byte offset in the file

        Returns:
            The line of code containing the offset, stripped of whitespace
        """
        try:
            with open(file_path, "rb") as f:
                content = f.read()

            # Find line boundaries around the offset
            line_start = content.rfind(b"\n", 0, offset) + 1
            line_end = content.find(b"\n", offset)
            if line_end == -1:
                line_end = len(content)

            # Extract the line
            line = content[line_start:line_end]

            # Decode and strip
            try:
                return line.decode("utf-8", errors="replace").strip()
            except Exception:
                return line.decode("latin-1", errors="replace").strip()

        except Exception as e:
            log.debug(
                f"Failed to extract line at offset {offset} from {file_path}: {e}"
            )
            return ""

    def get_lines_around_offset(
        self, file_path: str, offset: int, before: int, after: int
    ) -> str:
        """
        Extract a window of lines around a given byte offset.

        Returns the matched line plus `before` lines preceding it and `after`
        lines following it, joined by newlines. Leading/trailing blank lines
        are stripped but interior structure is preserved.
        """
        try:
            with open(file_path, "rb") as f:
                content = f.read()

            line_start = content.rfind(b"\n", 0, offset) + 1
            line_end = content.find(b"\n", offset)
            if line_end == -1:
                line_end = len(content)

            start = line_start
            for _ in range(before):
                if start <= 0:
                    break
                prev = content.rfind(b"\n", 0, start - 1)
                start = prev + 1 if prev != -1 else 0

            end = line_end
            for _ in range(after):
                if end >= len(content):
                    break
                nxt = content.find(b"\n", end + 1)
                end = nxt if nxt != -1 else len(content)

            window = content[start:end]
            try:
                text = window.decode("utf-8", errors="replace")
            except Exception:
                text = window.decode("latin-1", errors="replace")
            return text.strip("\n")

        except Exception as e:
            log.debug(
                f"Failed to extract lines around offset {offset} from {file_path}: {e}"
            )
            return ""

    def _convert_to_findings(self, results: dict, rules_dict: dict) -> List[Finding]:
        """
        Convert rule match results to Finding objects for risk analysis

        Args:
            results: Dict of rule_name -> list of matches
            rules_dict: Dict of rule_name -> rule object

        Returns:
            List of Finding objects
        """
        findings = []

        for rule_name, matches in results.items():
            if not matches:
                continue

            # Handle both underscore and dash formats (YARA uses underscores in results)
            rule_name_dash = rule_name.replace("_", "-")

            if rule_name_dash not in rules_dict:
                continue

            rule = rules_dict[rule_name_dash]

            # Skip rules without risk metadata
            if not rule.identifies:
                continue

            # Validate metadata
            if not validate_identifies(rule.identifies):
                log.warning(
                    f"Rule {rule_name} has invalid 'identifies' field: {rule.identifies}"
                )
                continue

            if rule.mitre_tactics and not validate_mitre_tactics(rule.mitre_tactics):
                log.warning(f"Rule {rule_name} has invalid MITRE tactics")

            # Convert severity/specificity/sophistication strings to Level enum
            try:
                severity = Level(rule.severity) if rule.severity else Level.MEDIUM
            except ValueError:
                log.warning(
                    f"Rule {rule_name} has invalid severity: {rule.severity}, using MEDIUM"
                )
                severity = Level.MEDIUM

            try:
                specificity = (
                    Level(rule.specificity) if rule.specificity else Level.MEDIUM
                )
            except ValueError:
                log.warning(
                    f"Rule {rule_name} has invalid specificity: {rule.specificity}, using MEDIUM"
                )
                specificity = Level.MEDIUM

            try:
                sophistication = (
                    Level(rule.sophistication) if rule.sophistication else Level.MEDIUM
                )
            except ValueError:
                log.warning(
                    f"Rule {rule_name} has invalid sophistication: {rule.sophistication}, using MEDIUM"
                )
                sophistication = Level.MEDIUM

            # Create Finding for each match
            for match in matches:
                finding = Finding(
                    rule_name=rule_name,
                    file_path=(
                        match.get("location", "").split(":")[0]
                        if isinstance(match, dict)
                        else ""
                    ),
                    identifies=rule.identifies,
                    severity=severity,
                    mitre_tactics=rule.mitre_tactics or [],
                    specificity=specificity,
                    sophistication=sophistication,
                    max_hits=rule.max_hits,  # Pass max_hits from rule
                    location=match.get("location") if isinstance(match, dict) else None,
                    code_snippet=match.get("code") if isinstance(match, dict) else None,
                    message=match.get("message") if isinstance(match, dict) else None,
                )
                findings.append(finding)

        return findings

    def _convert_metadata_to_findings(self, metadata_results: dict) -> List[Finding]:
        """
        Convert metadata rule results to Finding objects for risk analysis

        Args:
            metadata_results: Results from analyze_metadata

        Returns:
            List of Finding objects
        """
        findings = []

        for rule_name, message in metadata_results.get("results", {}).items():
            if not message:
                continue

            detector = self.metadata_detectors.get(rule_name)
            if not detector or not detector.identifies:
                continue

            if not validate_identifies(detector.identifies):
                log.warning(
                    f"Metadata rule {rule_name} has invalid 'identifies': {detector.identifies}"
                )
                continue

            mitre_tactics = (
                [t.strip() for t in detector.mitre_tactics.split(",") if t.strip()]
                if detector.mitre_tactics
                else []
            )

            try:
                severity = (
                    Level(detector.severity) if detector.severity else Level.MEDIUM
                )
            except ValueError:
                severity = Level.MEDIUM

            try:
                specificity = (
                    Level(detector.specificity)
                    if detector.specificity
                    else Level.MEDIUM
                )
            except ValueError:
                specificity = Level.MEDIUM

            try:
                sophistication = (
                    Level(detector.sophistication)
                    if detector.sophistication
                    else Level.MEDIUM
                )
            except ValueError:
                sophistication = Level.MEDIUM

            finding = Finding(
                rule_name=rule_name,
                file_path="",
                identifies=detector.identifies,
                severity=severity,
                mitre_tactics=mitre_tactics,
                specificity=specificity,
                sophistication=sophistication,
                max_hits=None,
                location=None,
                code_snippet=None,
                message=message,
            )
            findings.append(finding)

        return findings

    def calculate_package_risk_score(
        self, sourcecode_results: dict, metadata_results: Optional[dict] = None
    ) -> dict:
        """
        Calculate risk-based score for the package using the risk engine

        Args:
            sourcecode_results: Results from analyze_sourcecode
            metadata_results: Results from analyze_metadata

        Returns:
            Dict with risk score information
        """
        # Build rules dictionary for lookup
        rules_dict = {
            rule.id: rule for rule in get_sourcecode_rules(self.ecosystem, YaraRule)
        }

        # Convert sourcecode results to Finding objects
        all_findings = self._convert_to_findings(
            sourcecode_results["results"], rules_dict
        )

        # Convert metadata results to Finding objects
        if metadata_results:
            metadata_findings = self._convert_metadata_to_findings(metadata_results)
            all_findings.extend(metadata_findings)

        if not all_findings:
            log.debug("No findings with risk metadata to analyze")
            return {
                "score": 0.0,
                "label": "no_risks_detected",
                "risks": [],
                "findings_count": 0,
                "score_breakdown": {},
            }

        # Form risks at package level (not per-file)
        # This allows correlation of capabilities and threats across different files
        all_risks = form_risks_from_findings(all_findings)
        log.debug(f"Formed {len(all_risks)} risk(s) at package level")

        # Calculate overall package score
        risk_score = calculate_risk_score(all_risks)

        log.debug(
            f"Package risk score: {risk_score.score}/10 ({risk_score.label.value})"
        )

        return {
            "score": risk_score.score,
            "label": risk_score.label.value,
            "findings_count": len(all_findings),
            "score_breakdown": risk_score.score_breakdown,
            "_risks": all_risks,  # Internal: Risk objects for caller to format
        }
