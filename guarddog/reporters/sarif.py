import hashlib
import json
import os.path

import yaml

from guarddog.analyzer.metadata import get_metadata_detectors
from guarddog.ecosystems import ECOSYSTEM


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
    dir_path = os.path.dirname(os.path.realpath(__file__))
    semgrep_rules_base_dir = os.path.join(dir_path, "..", "analyzer", "sourcecode")
    for file in os.listdir(semgrep_rules_base_dir):
        if not file.endswith('.yml') and not file.endswith('.yaml'):
            continue
        with open(os.path.join(semgrep_rules_base_dir, file), "r") as fd:
            content = yaml.safe_load(fd)
            for rule in content["rules"]:
                text = rule["description"] if "description" in rule else rule["message"]
                rules_documentation[rule["id"]] = text
    return rules_documentation


def get_sarif_log(runs):
    """
    https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning#sariflog-object
    """
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": runs
    }


def get_run(results, driver):
    """
    https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning#run-object
    """
    return {
        "tool": {
            "driver": driver
        },
        "results": results
    }


def get_driver(rules, ecosystem: str):
    """
    https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning#toolcomponent-object
    """
    return {
        "name": f"GuardDog-{ecosystem}",
        "rules": rules
    }


def get_rule(rule_name: str, rules_documentation) -> dict:
    """
    https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning#reportingdescriptor-object
    """
    message = rules_documentation[rule_name] if rules_documentation[rule_name] is not None else ""
    return {
        "id": rule_name,
        "defaultConfiguration": {
            "level": "warning"
        },
        "shortDescription": {
            "text": f"GuardDog rule: {rule_name}"
        },
        "fullDescription": {
            "text": message
        },
        "help": {
            "text": message,
            "markdown": message
        },
        "properties": {
            "precision": "medium"
        }
    }


def get_result(rule_name, locations, text, partial_fingerprints):
    """
    https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning#result-object
    """
    return {
        "ruleId": rule_name,
        "message": {
            "text": text
        },
        "locations": locations,
        "partialFingerprints": partial_fingerprints
    }


def get_location(physical_location):
    """
    https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning#location-object
    """
    return {
        "physicalLocation": physical_location
    }


def get_physical_location(uri, region):
    """
    https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning#physicallocation-object
    """
    return {
        "artifactLocation": {
            "uri": uri
        },
        "region": region
    }


def get_region(package_raw: str, package: str) -> dict:
    start_line = 0
    start_column = 0
    end_column = 0
    for idx, val in enumerate(package_raw.split("\n")):
        if package in val:
            start_line = idx + 1
            start_column = val.index(package) + 1
            end_column = start_column + len(package)

    return {
        "startLine": start_line,
        "endLine": start_line,
        "startColumn": start_column,
        "endColumn": end_column,
    }


def report_verify_sarif(package_path: str, rule_names: list[str], scan_results: list[dict],
                        ecosystem: ECOSYSTEM) -> str:
    rules_documentation = build_rules_help_list()
    rules = list(map(
        lambda s: get_rule(s, rules_documentation),
        rule_names
    ))
    driver = get_driver(rules, ecosystem.value)
    results = []

    with open(package_path, "r") as file:
        package_raw = file.read()

    for entry in scan_results:
        if entry["result"]["issues"] == 0:
            continue

        region = get_region(package_raw, entry["dependency"])
        uri = package_path[2:] if package_path.startswith('./') else package_path
        physical_location = get_physical_location(uri, region)
        location = get_location(physical_location)
        scan_result_details = entry["result"]["results"]
        package = entry["dependency"]
        version = entry["version"]
        for rule_name in scan_result_details.keys():
            if scan_result_details[rule_name] is None or len(scan_result_details[rule_name]) == 0:
                continue
            text = f"On package: {package} version: {version}\n" + "\n".join(map(
                lambda x: x["message"],
                scan_result_details[rule_name]
            )) if isinstance(scan_result_details[rule_name], list) else scan_result_details[rule_name]
            key = f"{rule_name}-{text}"
            partial_fingerprints = {
                f"guarddog/v1/{rule_name}": hashlib.sha256(key.encode('utf-8')).hexdigest()
            }
            result = get_result(rule_name,
                                [location],
                                text,
                                partial_fingerprints)
            results.append(result)

    runs = get_run(results, driver)
    log = get_sarif_log([runs])
    return json.dumps(log, indent=2)
