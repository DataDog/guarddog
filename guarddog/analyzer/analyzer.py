import json
import logging
import os
import subprocess
import yara  # type: ignore
import ast

from collections import defaultdict
from pathlib import Path
from typing import Iterable, Optional, Dict

from guarddog.analyzer.metadata import get_metadata_detectors
from guarddog.analyzer.sourcecode import get_sourcecode_rules, SempgrepRule, YaraRule
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
        If setup.py, code-execution.py, or __init__.py exists, scans those files and their local imports

        Args:
            path (str): path to directory of package
            rules (set, optional): Set of source code rules to analyze. Defaults to all rules.

        Returns:
            dict[str]: map from each source code rule and their corresponding output
        """
        path_obj = Path(path)
        target_files = self._find_target_files(path_obj)

        if target_files:
            files_to_scan = [str(f) for f in target_files]

            # Resolve and add imported files
            project_root = path_obj if path_obj.is_dir() else path_obj.parent
            for target_file in target_files:
                imported_files = self._resolve_local_imports(str(target_file), str(project_root))
                files_to_scan.extend(imported_files)

            # Remove duplicates
            files_to_scan = list(dict.fromkeys(files_to_scan))

        else:
            files_to_scan = path

        semgrepscan_results = self.analyze_semgrep(files_to_scan, rules)
        yarascan_results = self.analyze_yara(path, rules)

        # Concatenate dictionaries together
        issues = semgrepscan_results["issues"] + yarascan_results["issues"]
        results = semgrepscan_results["results"] | yarascan_results["results"]
        errors = semgrepscan_results["errors"] | yarascan_results["errors"]

        return {"issues": issues, "errors": errors, "results": results, "path": path}

    def _find_target_files(self, path_obj: Path) -> list[Path]:
        """
        Find target files in the given path

        Args:
            path_obj (Path): directory or file path to search for target files

        Returns:
            list[Path]: list of Path objects that matches found target files
        """
        target_names = ["setup.py", "code-execution.py", "__init__.py"]
        found_files = []

        if not path_obj.is_dir():
            return [path_obj] if path_obj.name in target_names else []

        # Check root dir
        for target_name in target_names:
            if (path_obj / target_name).exists():
                found_files.append(path_obj / target_name)

        # Check one level deep in case root directory contains nothing but the package dir
        for item in path_obj.iterdir():
            if item.is_dir():
                for target_name in target_names:
                    if (item / target_name).exists():
                        found_files.append(item / target_name)

        return found_files

    def _resolve_local_imports(self, file_path: str, project_root: str, seen: Optional[set] = None, depth: int = 0,
                               max_depth: int = 50) -> set:
        """
        Recursively resolve all local imports from a given file

        Args:
            file_path (str): path to the Python file to analyze
            project_root (str): root directory of the project
            seen (set, optional): set of processed files
            depth (int): current recursion depth
            max_depth (int): maximum recursion depth

        Returns:
            set: set of absolute paths to locally imported files
        """
        if seen is None:
            seen = set()

        if depth > max_depth:
            log.warning(f"Exceeded maximum import depth ({max_depth}) at {file_path}.")
            return set()

        file_path_obj = Path(file_path).resolve()
        project_root_obj = Path(project_root).resolve()

        if str(file_path_obj) in seen:
            return set()
        seen.add(str(file_path_obj))

        try:
            with open(file_path_obj, "r", encoding="utf-8") as f:
                tree = ast.parse(f.read(), filename=str(file_path_obj))
        except Exception as e:
            log.debug(f"Failed to parse {file_path_obj}: {e}")
            return set()

        imported_files: set[str] = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module_name = alias.name.split(".")[0]  # Get top level module
                    self._add_if_local(module_name, file_path_obj, project_root_obj, imported_files, seen, depth)

            elif isinstance(node, ast.ImportFrom):
                if node.level > 0:  # Relative import
                    base_path = file_path_obj.parent
                    for _ in range(node.level - 1):
                        base_path = base_path.parent

                    module_name = node.module.split(".")[0] if node.module else ""
                    if module_name:
                        self._check_relative_import(module_name, base_path, project_root_obj, imported_files,
                                                    seen, depth)
                    else:
                        # from . import x
                        for alias in node.names:
                            self._check_relative_import(alias.name, base_path, project_root_obj, imported_files,
                                                        seen, depth)
                elif node.module and "." not in node.module:
                    # Absolute import of simple module
                    self._add_if_local(node.module, file_path_obj, project_root_obj, imported_files, seen, depth)

        return imported_files

    def _add_if_local(self, module_name: str, current_file: Path, project_root: Path, imported_files: set[str],
                      seen: set, depth: int) -> None:
        """
        Add module to imported_files set if it exists locally within the project

        Args:
            module_name (str): name of the module to check
            current_file (Path): path of the file performing the import
            project_root (Path): root directory of the project
            imported_files (set[str]): set of already identified imported file paths
            seen (set): set of files already processed
            depth (int): current recursion depth

        Returns:
            None
        """
        candidates = [
            project_root / f"{module_name}.py",
            project_root / module_name / "__init__.py",
            current_file.parent / f"{module_name}.py",
            current_file.parent / module_name / "__init__.py",
        ]

        for candidate in candidates:
            if self._is_valid_local_file(candidate, project_root, seen):
                imported_files.add(str(candidate))
                imported_files.update(
                    self._resolve_local_imports(str(candidate), str(project_root), seen, depth + 1)
                )
                return

    def _check_relative_import(self, name: str, base_path: Path, project_root: Path, imported_files: set[str],
                               seen: set, depth: int) -> None:
        """
        Resolve a relative import and add the corresponding file to the imported_files set

        Args:
            name (str): module or file name to resolve
            base_path (Path): base directory for relative import resolution
            project_root (Path): root directory of the project
            imported_files (set[str]): set of already identified imported file paths
            seen (set): set of files already processed
            depth (int): current recursion depth

        Returns:
            None
        """
        candidates = [
            base_path / f"{name}.py",
            base_path / name / "__init__.py",
        ]

        for candidate in candidates:
            if self._is_valid_local_file(candidate, project_root, seen):
                imported_files.add(str(candidate))
                imported_files.update(
                    self._resolve_local_imports(str(candidate), str(project_root), seen, depth + 1)
                )
                return

    def _is_valid_local_file(self, candidate: Path, project_root: Path, seen: set) -> bool:
        """
        Check if a candidate file exists, is within project, and hasn't been seen

        Args:
            candidate (Path): file path to validate
            project_root (Path): root directory of the project
            seen (set): set of already processed file paths

        Returns:
            bool: true if the file is valid and local, false otherwise
        """
        try:
            candidate = candidate.resolve()
            if not candidate.exists() or not candidate.is_file() or str(candidate) in seen:
                return False

            # Check if within project root
            try:
                return candidate.is_relative_to(project_root)
            except AttributeError:  # Python < 3.9
                return project_root in candidate.parents or candidate == project_root
        except (OSError, ValueError):
            return False

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

        try:
            scan_rules = yara.compile(filepaths=rules_path)

            for root, _, files in os.walk(path):
                for f in files:
                    # Skip files with excluded extensions
                    if f.lower().endswith(tuple(YARA_EXT_EXCLUDE)):
                        continue

                    scan_file_target_abspath = os.path.join(root, f)
                    scan_file_target_relpath = os.path.relpath(
                        scan_file_target_abspath, path
                    )

                    matches = scan_rules.match(scan_file_target_abspath)
                    for m in matches:

                        for s in m.strings:
                            for i in s.instances:
                                finding = {
                                    "location": f"{scan_file_target_relpath}:{i.offset}",
                                    "code": self.trim_code_snippet(str(i.matched_data)),
                                    "message": m.meta.get(
                                        "description", f"{m.rule} rule matched"
                                    ),
                                }

                                # since yara can match the multiple times in the same file
                                # leading to finding several times the same word or pattern
                                # this dedup the matches
                                if [
                                    f
                                    for f in rule_results[m.rule]
                                    if finding["code"] == f["code"]
                                ]:
                                    continue

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
        # Convert single path to list
        if isinstance(path, str):
            path = [path]

        log.debug("Running semgrep rules")

        all_rules = self.semgrep_ruleset
        if rules is not None:
            # filtering the full ruleset witht the user's input
            all_rules = self.semgrep_ruleset & rules

        results: Dict[str, dict] = {rule: {} for rule in all_rules}
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
            response = self._invoke_semgrep(targets=path, rules=rules_path)
            rule_results = self._format_semgrep_response(response)
            issues += sum(len(res) for res in rule_results.values())

            results = results | rule_results
        except Exception as e:
            errors["rules-all"] = f"failed to run rule: {str(e)}"

        return {"results": results, "errors": errors, "issues": issues}

    def _invoke_semgrep(self, targets: list, rules: Iterable[str]):
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
                cmd.extend(["--exclude", excluded])

            cmd.append(f"--timeout={SEMGREP_TIMEOUT}")
            cmd.append("--no-git-ignore")
            cmd.append("--json")
            cmd.append("--quiet")
            cmd.append("--disable-nosem")
            cmd.append(f"--max-target-bytes={SEMGREP_MAX_TARGET_BYTES}")
            cmd.extend(targets)

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

        results: defaultdict[str, list[dict]] = defaultdict(list)

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

            location = os.path.basename(file_path) + ":" + str(start_line)

            finding = {
                "location": location,
                "code": code,
                "message": result["extra"]["message"],
            }

            if finding not in results[rule_name]:
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
