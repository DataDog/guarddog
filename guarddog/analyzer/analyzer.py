import json
import logging
import os
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Iterable, List, Optional

from guarddog.analyzer.metadata import get_metadata_detectors
from guarddog.analyzer.sourcecode import SOURCECODE_RULES
from guarddog.ecosystems import ECOSYSTEM

SEMGREP_MAX_TARGET_BYTES = 10_000_000

log = logging.getLogger("guarddog")


class Analyzer:
    """
    Analyzes a local directory for threats found by source code or metadata rules

    Attributes:
        sourcecode_rules_path (str): path to source code rules
        ecosystem (str): name of the current ecosystem
        metadata_ruleset (list): list of metadata rule names
        sourcecode_ruleset (list): list of source code rule names

        exclude (list): list of directories to exclude from source code search

        metadata_detectors(list): list of metadata detectors
    """

    def __init__(self, ecosystem=ECOSYSTEM.PYPI) -> None:
        self.sourcecode_rules_path = os.path.join(os.path.dirname(__file__), "sourcecode")

        self.ecosystem = ecosystem

        # Rules and associated detectors
        self.metadata_detectors = get_metadata_detectors(ecosystem)

        self.metadata_ruleset = self.metadata_detectors.keys()
        self.sourcecode_ruleset = [rule["id"] for rule in SOURCECODE_RULES[ecosystem]]

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
        metadata_rules = None
        sourcecode_rules = None
        if rules is not None:
            # Only run specific rules
            sourcecode_rules = set()
            metadata_rules = set()

            for rule in rules:
                if rule in self.sourcecode_ruleset:
                    log.debug(f"Using source code rule {rule}")
                    sourcecode_rules.add(rule)
                elif rule in self.metadata_ruleset:
                    log.debug(f"Using metadata rule {rule}")
                    metadata_rules.add(rule)
                else:
                    raise Exception(f"{rule} is not a valid rule.")

        log.debug(f"Running metadata rules against package '{name}'")
        metadata_results = self.analyze_metadata(path, info, metadata_rules, name, version)

        log.debug(f"Running source code rules against directory '{path}'")
        sourcecode_results = self.analyze_sourcecode(path, sourcecode_rules)

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

        all_rules = rules if rules is not None else self.metadata_ruleset
        results = {}
        errors = {}
        issues = 0

        for rule in all_rules:
            try:
                log.debug(f"Running rule {rule} against package '{name}'")
                rule_matches, message = self.metadata_detectors[rule].detect(info, path, name, version)
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
        targetpath = Path(path)
        all_rules = rules if rules is not None else self.sourcecode_ruleset
        results = {rule: {} for rule in all_rules}  # type: dict
        errors = {}
        issues = 0

        rules_path: List[str]
        if rules is None:
            log.debug(f"No rules specified using full rules directory {self.sourcecode_rules_path}")
            rules_path = [self.sourcecode_rules_path]
        else:
            rules_path = list(map(
                lambda rule_name: os.path.join(self.sourcecode_rules_path, f"{rule_name}.yml"),
                rules
            ))

        if len(rules_path) == 0:
            log.debug("No source code rules to run")
            return {"results": {}, "errors": {}, "issues": 0}

        try:
            log.debug(f"Running source code rules against {path}")
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

            results[rule_name].append({
                'location': location,
                'code': code,
                'message': result["extra"]["message"]
            })

        return results

    # Makes sure the matching code to be displayed isn't too long
    def trim_code_snippet(self, code):
        THRESHOLD = 250
        if len(code) > THRESHOLD:
            return code[: THRESHOLD - 10] + '...' + code[len(code) - 10:]
        else:
            return code
