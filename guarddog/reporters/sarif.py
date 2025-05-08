import hashlib
import json

from guarddog.analyzer.sourcecode import get_sourcecode_rules
from guarddog.analyzer.metadata import get_metadata_detectors
from guarddog.ecosystems import ECOSYSTEM
from guarddog.reporters import BaseReporter
from guarddog.scanners.scanner import DependencyFile
from typing import List
from guarddog.reporters.human_readable import HumanReadableReporter


class SarifReporter(BaseReporter):
    """
    Sarif is a class that formats and prints scan results in the SARIF format.
    """

    @staticmethod
    def render_verify(
        dependency_files: List[DependencyFile],
        rule_names: list[str],
        scan_results: list[dict],
        ecosystem: ECOSYSTEM,
    ) -> tuple[str, str]:
        """
        Report the scans results in the SARIF format.

        Args:
            scan_results (dict): The scan results to be reported.
        """

        def build_rules_help_list() -> dict:
            """
            Builds a dict with the names of all available rules and their documentation
            @return: dict[name_of_rule, rule_description]
            """
            rules_documentation = {}
            for ecosystem in ECOSYSTEM:
                rules = get_metadata_detectors(ecosystem)
                for name, instance in rules.items():
                    detector_class = instance.__class__.__base__
                    rules_documentation[name] = detector_class.__doc__
                for sourcecode_rule in get_sourcecode_rules(ecosystem):
                    rules_documentation[sourcecode_rule.id] = (
                        sourcecode_rule.description
                    )
            return rules_documentation

        def get_sarif_log(runs):
            """
            https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning#sariflog-object
            """
            return {
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "version": "2.1.0",
                "runs": runs,
            }

        def get_run(results, driver):
            """
            https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning#run-object
            """
            return {"tool": {"driver": driver}, "results": results}

        def get_driver(rules, ecosystem: str):
            """
            https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning#toolcomponent-object
            """
            return {
                "name": f"GuardDog-{ecosystem}",
                "informationUri": "https://github.com/DataDog/guarddog",
                "rules": rules,
            }

        def get_rule(rule_name: str, rules_documentation) -> dict:
            """
            https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning#reportingdescriptor-object
            """
            message = (
                rules_documentation[rule_name]
                if rules_documentation[rule_name] is not None
                else ""
            )
            return {
                "id": rule_name,
                "defaultConfiguration": {"level": "warning"},
                "shortDescription": {"text": f"GuardDog rule: {rule_name}"},
                "fullDescription": {"text": message},
                "help": {"text": message, "markdown": message},
                "properties": {"precision": "medium"},
            }

        def get_result(rule_name, locations, text, partial_fingerprints):
            """
            https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning#result-object
            """
            return {
                "ruleId": rule_name,
                "message": {"text": text},
                "locations": locations,
                "partialFingerprints": partial_fingerprints,
            }

        def get_location(physical_location):
            """
            https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning#location-object
            """
            return {"physicalLocation": physical_location}

        def get_physical_location(uri, region):
            """
            https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning#physicallocation-object
            """
            return {"artifactLocation": {"uri": uri}, "region": region}

        def get_region(
            dependency_files: List[DependencyFile], package: str
        ) -> tuple[DependencyFile, dict]:
            for dependency_file in dependency_files:
                for d in dependency_file.dependencies:
                    if d.name == package:
                        return dependency_file, {
                            "startLine": d.versions[0].location,
                            "endLine": d.versions[0].location,
                            "startColumn": 1,
                            "endColumn": len(package),
                        }
            raise ValueError(
                f"Could not find the package {package} in the dependency files"
            )

        rules_documentation = build_rules_help_list()
        rules = list(map(lambda s: get_rule(s, rules_documentation), rule_names))
        driver = get_driver(rules, ecosystem.value)
        results = []

        for entry in scan_results:
            if entry["result"]["issues"] == 0:
                continue

            dep_file, region = get_region(
                dependency_files=dependency_files, package=entry["dependency"]
            )
            package_path = dep_file.name
            uri = package_path[2:] if package_path.startswith("./") else package_path
            physical_location = get_physical_location(uri, region)
            location = get_location(physical_location)
            scan_result_details = entry["result"]["results"]
            package = entry["dependency"]
            version = entry["version"]
            for rule_name in scan_result_details.keys():
                if (
                    scan_result_details[rule_name] is None
                    or len(scan_result_details[rule_name]) == 0
                ):
                    continue

                text = (
                    f"On package: {package} version: {version}\n"
                    + "\n".join(
                        map(
                            lambda x: f"{x['message']} in file {x['location']}",
                            scan_result_details[rule_name],
                        )
                    )
                    if isinstance(scan_result_details[rule_name], list)
                    else scan_result_details[rule_name]
                )
                key = f"{rule_name}-{text}"
                partial_fingerprints = {
                    f"guarddog/v1/{rule_name}": hashlib.sha256(
                        key.encode("utf-8")
                    ).hexdigest()
                }
                result = get_result(rule_name, [location], text, partial_fingerprints)
                results.append(result)

        runs = get_run(results, driver)
        log = get_sarif_log([runs])

        errors = "\n".join(
            map(
                lambda r: "\n".join(
                    HumanReadableReporter.print_errors(
                        identifier=r["dependency"], results=r["result"]
                    )
                ),
                scan_results,
            )
        )

        return (json.dumps(log, indent=2), errors)
