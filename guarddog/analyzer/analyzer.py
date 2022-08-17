import os
from pathlib import Path

from semgrep.semgrep_main import invoke_semgrep

from guarddog.analyzer.metadata.compromised_email import CompromisedEmailDetector
from guarddog.analyzer.metadata.empty_information import EmptyInfoDetector
from guarddog.analyzer.metadata.typosquatting import TyposquatDetector


class Analyzer:
    """
    Analyzes a local directory for threats found by source code or metadata rules

    Attributes:
        metadata_path (str): path to metadata rules
        sourcecode_path (str): path to source code rules

        metadata_ruleset (list): list of metadata rule names
        sourcecode_ruleset (list): list of source code rule names

        exclude (list): list of directories to exclude from source code search

        metadata_detectors(list): list of metadata detectors
    """

    def __init__(self) -> None:
        self.metadata_path = os.path.join(os.path.dirname(__file__), "metadata")
        self.sourcecode_path = os.path.join(os.path.dirname(__file__), "sourcecode")

        # Define sourcecode and metadata rulesets
        def get_rules(file_extension, path):
            return set(rule.replace(file_extension, "") for rule in os.listdir(path) if rule.endswith(file_extension))

        self.metadata_ruleset = get_rules(".py", self.metadata_path)
        self.sourcecode_ruleset = get_rules(".yml", self.sourcecode_path)

        self.metadata_ruleset.remove("detector")
        self.metadata_ruleset.remove("__init__")

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

        # Rules and associated detectors
        self.metadata_detectors = {
            "typosquatting": TyposquatDetector(),
            "compromised_email": CompromisedEmailDetector(),
            "empty_information": EmptyInfoDetector(),
        }

    def analyze(self, path, info=None, rules=None) -> dict[str]:
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
        if rules is None:
            metadata_results = self.analyze_metadata(info)
            sourcecode_results = self.analyze_sourcecode(path)
        else:
            sourcecode_rules = set()
            metadata_rules = set()

            for rule in rules:
                if rule in self.sourcecode_ruleset:
                    sourcecode_rules.add(rule)
                elif rule in self.metadata_ruleset:
                    metadata_rules.add(rule)
                else:
                    raise Exception(f"{rule} is not a valid rule.")

            metadata_results = self.analyze_metadata(info, metadata_rules)
            sourcecode_results = self.analyze_sourcecode(path, sourcecode_rules)

        # Concatenate dictionaries together
        issues = metadata_results["issues"] + sourcecode_results["issues"]
        results = metadata_results["results"] | sourcecode_results["results"]
        errors = metadata_results["errors"] | sourcecode_results["errors"]

        return {"issues": issues, "errors": errors, "results": results}

    def analyze_metadata(self, info, rules=None) -> dict[str]:
        """
        Analyzes the metadata of a given package

        Args:
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
                rule_results = self.metadata_detectors[rule].detect(info)
                issues += bool(rule_results)  # only True if results nonempty
                results[rule] = rule_results
            except Exception as e:
                errors[rule] = str(e)

        return {"results": results, "errors": errors, "issues": issues}

    def analyze_sourcecode(self, path, rules=None) -> tuple[dict, int]:
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

        results = {rule: {} for rule in all_rules}
        errors = {}
        issues = 0

        if rules is None:
            response = invoke_semgrep(Path(self.sourcecode_path), [targetpath], exclude=self.exclude, no_git_ignore=True)
            results = results | self._format_semgrep_response(response, targetpath=targetpath)
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
                    errors[rule] = str(e)

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

            if rule_name not in results:
                results[rule_name] = {location: code_snippet}
            else:
                results[rule_name][location] = code_snippet

        return results
