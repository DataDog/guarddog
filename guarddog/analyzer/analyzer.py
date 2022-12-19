import os
from pathlib import Path
from typing import Optional

from semgrep.semgrep_main import invoke_semgrep  # type: ignore

from guarddog.analyzer.metadata import get_metadata_detectors
from guarddog.ecosystems import ECOSYSTEM


def get_rules(file_extension, path):
    return set(rule.replace(file_extension, "") for rule in os.listdir(path) if rule.endswith(file_extension))


SEMGREP_RULES_PATH = os.path.join(os.path.dirname(__file__), "sourcecode")
SEMGREP_RULE_NAMES = get_rules(".yml", SEMGREP_RULES_PATH)


class Analyzer:
    """
    Analyzes a local directory for threats found by source code or metadata rules

    Attributes:
        sourcecode_path (str): path to source code rules
        ecosystem (str): name of the current ecosystem
        metadata_ruleset (list): list of metadata rule names
        sourcecode_ruleset (list): list of source code rule names

        exclude (list): list of directories to exclude from source code search

        metadata_detectors(list): list of metadata detectors
    """

    def __init__(self, ecosystem=ECOSYSTEM.PYPI) -> None:
        self.sourcecode_path = os.path.join(os.path.dirname(__file__), "sourcecode")

        self.ecosystem = ecosystem

        # Rules and associated detectors
        self.metadata_detectors = get_metadata_detectors(ecosystem)

        self.metadata_ruleset = self.metadata_detectors.keys()
        self.sourcecode_ruleset = SEMGREP_RULE_NAMES

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
                    sourcecode_rules.add(rule)
                elif rule in self.metadata_ruleset:
                    metadata_rules.add(rule)
                else:
                    raise Exception(f"{rule} is not a valid rule.")

        metadata_results = self.analyze_metadata(path, info, metadata_rules, name, version)
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

        if rules is None:
            # No rule specified, run all rules
            try:
                response = invoke_semgrep(Path(self.sourcecode_path), [targetpath], exclude=self.exclude,
                                          no_git_ignore=True)
                rule_results = self._format_semgrep_response(response, targetpath=targetpath)
                issues += len(rule_results)

                results = results | rule_results
            except Exception as e:
                errors["rules-all"] = f"failed to run rule: {str(e)}"
        else:
            for rule in rules:
                try:
                    response = invoke_semgrep(
                        Path(os.path.join(self.sourcecode_path, rule + ".yml")),
                        [targetpath],
                        exclude=self.exclude,
                        no_git_ignore=True,
                    )
                    rule_results = self._format_semgrep_response(response, rule=rule, targetpath=targetpath)
                    issues += len(rule_results)

                    results = results | rule_results
                except Exception as e:
                    errors[rule] = f"failed to run rule {rule}: {str(e)}"

        return {"results": results, "errors": errors, "issues": issues}

    def _format_semgrep_response(self, response, rule=None, targetpath=None):
        """
        Formats the response from Semgrep

        Args:
            response (dict): response from Semgrep
            rule (str, optional): name of rule to format. Defaults to all rules.
            targetpath (str, optional): root directory of scan. Defaults to None.
                Paths in formatted resonse will be rooted from targetpath.

        Returns:
            dict: formatted response in the form...

            {
                ...
                <rule-name>: {
                    <path-to-code:line-num>: <dangerous-code>
                    ...
                },
                ...
            }
        """

        results = {}

        for result in response["results"]:
            rule_name = rule or result["check_id"].split(".")[-1]
            code_snippet = result["extra"]["lines"]
            line = result["start"]["line"]

            file_path = os.path.abspath(result["path"])
            if targetpath:
                file_path = os.path.relpath(file_path, targetpath)

            location = file_path + ":" + str(line)
            code = self.trim_code_snippet(code_snippet)

            if rule_name not in result:
                results[rule_name] = []
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
