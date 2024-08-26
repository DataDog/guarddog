import json
import logging
import os
import subprocess
import yara  # type: ignore

from collections import defaultdict
from pathlib import Path
from typing import Iterable, Optional, Dict

from guarddog.analyzer.metadata import get_metadata_detectors
from guarddog.analyzer.sourcecode import get_sourcecode_rules, SempgrepRule, YaraRule
from guarddog.utils.config import YARA_EXT_EXCLUDE
from guarddog.ecosystems import ECOSYSTEM

SEMGREP_MAX_TARGET_BYTES = 10_000_000
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

    def analyze(self, path, info=None, rules=None, name: Optional[str] = None, version: Optional[str] = None) -> dict:
        """
        Analyzes a package in the given path

        Args:
            path (str): path to package
            info (dict, optional): Any package information to analyze metadata. Defaults to None.
            rules (set, optional): Set of rules to analyze. Defaults to all rules.

        Raises:
            Exception: "{rule} is not a valid rule."

        Returns:
            dict[str]: map from each rule and their corresponding output
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

        return {"issues": issues, "errors": errors, "results": results, "path": path}

    def analyze_metadata(self, path: str, info, rules=None, name: Optional[str] = None,
                         version: Optional[str] = None) -> dict:
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
                rule_matches, message = self.metadata_detectors[rule].detect(info, path, name, version)
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

        rule_results = defaultdict(list)

        rules_path = {
            rule_name: os.path.join(SOURCECODE_RULES_PATH, f"{rule_name}.yar")
            for rule_name in all_rules
        }

        if len(rules_path) == 0:
            log.debug("No yara rules to run")
            return {"results": results, "errors": errors, "issues": issues}

        try:
            scan_rules = yara.compile(filepaths=rules_path)

            for root, _, files in os.walk(path):
                for f in files:
                    # Skip files with excluded extensions
                    if f.lower().endswith(tuple(YARA_EXT_EXCLUDE)):
                        continue

                    scan_file_target_abspath = os.path.join(root, f)
                    scan_file_target_relpath = os.path.relpath(scan_file_target_abspath, path)

                    matches = scan_rules.match(scan_file_target_abspath)
                    for m in matches:
                        for s in m.strings:
                            for i in s.instances:
                                finding = {
                                    "location": f"{scan_file_target_relpath}:{i.offset}",
                                    "code": self.trim_code_snippet(str(i.matched_data)),
                                    'message': m.meta.get("description", f"{m.rule} rule matched")
                                }
                                issues += len(m.strings)
                                rule_results[m.rule].append(finding)
        except Exception as e:
            errors["rules-all"] = f"failed to run rule: {str(e)}"

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

        rules_path = list(map(
            lambda rule_name: os.path.join(SOURCECODE_RULES_PATH, f"{rule_name}.yml"),
            all_rules
        ))

        if len(rules_path) == 0:
            log.debug("No semgrep code rules to run")
            return {"results": {}, "errors": {}, "issues": 0}

        try:
            log.debug(f"Running semgrep code rules against {path}")
            response = self._invoke_semgrep(target=path, rules=rules_path)
            rule_results = self._format_semgrep_response(response, targetpath=targetpath)
            issues += sum(len(res) for res in rule_results.values())

            results = results | rule_results
        except Exception as e:
            errors["rules-all"] = f"failed to run rule: {str(e)}"

        return {"results": results, "errors": errors, "issues": issues}

    def _invoke_semgrep(self, target: str, rules: Iterable[str]):
        try:
            cmd = ["semgrep"]
            for rule in rules:
                cmd.extend(["--config", rule])

            for excluded in self.exclude:
                cmd.append(f"--exclude='{excluded}'")
            cmd.append("--no-git-ignore")
            cmd.append("--json")
            cmd.append("--quiet")
            cmd.append(f"--max-target-bytes={SEMGREP_MAX_TARGET_BYTES}")
            cmd.append(target)
            log.debug(f"Invoking semgrep with command line: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, check=True, encoding="utf-8")
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
            code_snippet = result["extra"]["lines"]
            line = result["start"]["line"]

            file_path = os.path.abspath(result["path"])
            if targetpath:
                file_path = os.path.relpath(file_path, targetpath)

            location = file_path + ":" + str(line)
            code = self.trim_code_snippet(code_snippet)

            finding = {
                'location': location,
                'code': code,
                'message': result["extra"]["message"]
            }

            rule_results = results[rule_name]
            if finding in rule_results:
                continue
            results[rule_name].append(finding)

        return results

    # Makes sure the matching code to be displayed isn't too long
    def trim_code_snippet(self, code):
        THRESHOLD = 250
        if len(code) > THRESHOLD:
            return code[: THRESHOLD - 10] + '...' + code[len(code) - 10:]
        else:
            return code
