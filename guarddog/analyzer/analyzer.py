import json
import logging
import os
import subprocess
import yara  # type: ignore

from collections import defaultdict
from fnmatch import fnmatch
from pathlib import Path
from typing import Iterable, Optional, Dict, List

from guarddog.analyzer.metadata import get_metadata_detectors
from guarddog.analyzer.sourcecode import get_sourcecode_rules, SempgrepRule, YaraRule
from guarddog.analyzer.risk_engine import (
    Finding,
    Level,
    form_risks_from_findings,
    calculate_risk_score,
    validate_identifies,
    validate_mitre_tactics,
)
from guarddog.utils.config import YARA_EXT_EXCLUDE
from guarddog.ecosystems import ECOSYSTEM

MAX_BYTES_DEFAULT = 10_000_000
SEMGREP_TIMEOUT_DEFAULT = 10

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
        self.semgrep_ruleset: set[str] = set(
            r.id for r in get_sourcecode_rules(ecosystem, SempgrepRule)
        )
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
            "semgrep",
            "migrations",
            ".github",
            ".semgrep_logs",
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

        # Calculate risk-based score
        risk_score = self.calculate_package_risk_score(sourcecode_results)

        # Extract and format risks for top-level output
        risk_objects = risk_score.pop("_risks", [])
        formatted_risks = [
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
        semgrepscan_results = self.analyze_semgrep(path, rules)

        yarascan_results = self.analyze_yara(path, rules)

        # Concatenate dictionaries together
        issues = semgrepscan_results["issues"] + yarascan_results["issues"]
        results = semgrepscan_results["results"] | yarascan_results["results"]
        errors = semgrepscan_results["errors"] | yarascan_results["errors"]

        return {"issues": issues, "errors": errors, "results": results, "path": path}

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

        rule_results: defaultdict[dict, list[dict]] = defaultdict(list)

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

                        matches = scan_rule.match(scan_file_target_abspath)
                        for m in matches:

                            for s in m.strings:
                                for i in s.instances:
                                    # Extract the actual line of code at the match offset
                                    line_of_code = self.get_line_at_offset(
                                        scan_file_target_abspath, i.offset
                                    )

                                    finding = {
                                        "location": f"{scan_file_target_relpath}:{i.offset}",
                                        "code": self.trim_code_snippet(line_of_code),
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

    def analyze_semgrep(self, path, rules=None) -> dict:
        """
        Analyzes the source code of a given package

        Args:
            path (str): path to directory of package
            rules (set, optional): Set of source code rules to analyze. Defaults to all rules.

        Returns:
            dict[str]: map from each source code rule and their corresponding output
        """
        log.debug(f"Running semgrep rules against directory '{path}'")

        targetpath = Path(path)
        all_rules = self.semgrep_ruleset
        if rules is not None:
            # filtering the full ruleset witht the user's input
            all_rules = self.semgrep_ruleset & rules

        results = {rule: {} for rule in all_rules}  # type: dict
        errors = {}
        issues = 0

        rules_path = list(
            map(
                lambda rule_name: os.path.join(
                    SOURCECODE_RULES_PATH, f"{rule_name}.yml"
                ),
                all_rules,
            )
        )

        if len(rules_path) == 0:
            log.debug("No semgrep code rules to run")
            return {"results": {}, "errors": {}, "issues": 0}

        try:
            log.debug(f"Running semgrep code rules against {path}")
            response = self._invoke_semgrep(target=path, rules=rules_path)
            rule_results = self._format_semgrep_response(
                response, targetpath=targetpath
            )
            issues += sum(len(res) for res in rule_results.values())

            results = results | rule_results
        except Exception as e:
            errors["rules-all"] = f"failed to run rule: {str(e)}"

        return {"results": results, "errors": errors, "issues": issues}

    def _invoke_semgrep(self, target: str, rules: Iterable[str]):
        try:
            SEMGREP_MAX_TARGET_BYTES = int(
                os.getenv("GUARDDOG_SEMGREP_MAX_TARGET_BYTES", MAX_BYTES_DEFAULT)
            )
            SEMGREP_TIMEOUT = int(
                os.getenv("GUARDDOG_SEMGREP_TIMEOUT", SEMGREP_TIMEOUT_DEFAULT)
            )
            cmd = ["semgrep"]
            for rule in rules:
                cmd.extend(["--config", rule])

            for excluded in self.exclude:
                cmd.append(f"--exclude='{excluded}'")
            cmd.append(f"--timeout={SEMGREP_TIMEOUT}")
            cmd.append("--no-git-ignore")
            cmd.append("--json")
            cmd.append("--quiet")
            cmd.append("--disable-nosem")
            cmd.append(f"--max-target-bytes={SEMGREP_MAX_TARGET_BYTES}")
            cmd.append(target)
            log.debug(f"Invoking semgrep with command line: {' '.join(cmd)}")
            result = subprocess.run(
                cmd, capture_output=True, check=True, encoding="utf-8"
            )
            return json.loads(str(result.stdout))
        except FileNotFoundError:
            raise Exception("unable to find semgrep binary")
        except subprocess.CalledProcessError as e:
            error_message = f"""
An error occurred when running Semgrep.

command: {" ".join(e.cmd)}
status code: {e.returncode}
output: {e.output}
"""
            raise Exception(error_message)
        except json.JSONDecodeError as e:
            raise Exception("unable to parse semgrep JSON output: " + str(e))
        except ValueError as e:
            raise Exception("Invalid environment variable value: " + str(e))

    def _format_semgrep_response(self, response, rule=None, targetpath=None):
        """
        Formats the response from Semgrep

        Args:
            response (dict): response from Semgrep
            rule (str, optional): name of rule to format. Defaults to all rules.
            targetpath (str, optional): root directory of scan. Defaults to None.
                Paths in formatted response will be rooted from targetpath.

        Returns:
            dict: formatted response in the form...

            {
                ...
                <rule-name>: [
                    {
                        <path-to-code:line-num>: <dangerous-code>
                        ...
                    },
                    ...
                ],
                ...
            }
        """

        results = defaultdict(list)

        for result in response["results"]:
            rule_name = rule or result["check_id"].split(".")[-1]
            start_line = result["start"]["line"]
            end_line = result["end"]["line"]

            file_path = os.path.abspath(result["path"])
            code = self.trim_code_snippet(
                self.get_snippet(
                    file_path=file_path, start_line=start_line, end_line=end_line
                )
            )
            if targetpath:
                file_path = os.path.relpath(file_path, targetpath)

            location = file_path + ":" + str(start_line)

            finding = {
                "location": location,
                "code": code,
                "message": result["extra"]["message"],
            }

            rule_results = results[rule_name]
            if finding in rule_results:
                continue
            results[rule_name].append(finding)

        return results

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

    # Makes sure the matching code to be displayed isn't too long
    def trim_code_snippet(self, code):
        THRESHOLD = 250
        if len(code) > THRESHOLD:
            return code[: THRESHOLD - 10] + "..." + code[len(code) - 10 :]
        else:
            return code

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
            with open(file_path, 'rb') as f:
                content = f.read()

            # Find line boundaries around the offset
            line_start = content.rfind(b'\n', 0, offset) + 1
            line_end = content.find(b'\n', offset)
            if line_end == -1:
                line_end = len(content)

            # Extract the line
            line = content[line_start:line_end]

            # Decode and strip
            try:
                return line.decode('utf-8', errors='replace').strip()
            except Exception:
                return line.decode('latin-1', errors='replace').strip()

        except Exception as e:
            log.debug(f"Failed to extract line at offset {offset} from {file_path}: {e}")
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

    def calculate_package_risk_score(self, sourcecode_results: dict) -> dict:
        """
        Calculate risk-based score for the package using the risk engine

        Args:
            sourcecode_results: Results from analyze_sourcecode

        Returns:
            Dict with risk score information
        """
        # Build rules dictionary for lookup
        rules_dict = {}
        for rule in get_sourcecode_rules(self.ecosystem, SempgrepRule):
            rules_dict[rule.id] = rule
        for rule in get_sourcecode_rules(self.ecosystem, YaraRule):
            rules_dict[rule.id] = rule

        # Convert results to Finding objects
        all_findings = self._convert_to_findings(
            sourcecode_results["results"], rules_dict
        )

        if not all_findings:
            log.debug("No findings with risk metadata to analyze")
            return {
                "score": 0.0,
                "label": "none",
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

        log.info(
            f"Package risk score: {risk_score.score}/10 ({risk_score.label.value})"
        )

        return {
            "score": risk_score.score,
            "label": risk_score.label.value,
            "findings_count": len(all_findings),
            "score_breakdown": risk_score.score_breakdown,
            "_risks": all_risks,  # Internal: Risk objects for caller to format
        }
