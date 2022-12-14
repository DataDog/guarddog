import hashlib
import json


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


def get_driver(rules):
    """
    https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning#toolcomponent-object
    """
    return {
        "name": "GuardDog",
        "rules": rules
    }


def get_rule(rule_name: str) -> dict:
    """
    https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning#reportingdescriptor-object
    """
    return {
        "id": rule_name,
        "defaultConfiguration": {
            "level": "warning"
        },
        "shortDescription": {
            "text": "TODO: I should not be this placeholder come on!"
        },
        "fullDescription": {
            "text": "TODO: I should not be this placeholder come on!"
        },
        "help": {
            "text": "TODO: I should not be this placeholder come on!"
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


def _get_npm_region(package_raw: str, package: str) -> dict:
    start_line = 0
    start_column = 0
    end_column = 0
    for idx, val in enumerate(package_raw.split("\n")):
        if package in val:
            start_line = idx + 1
            start_column = val.index(package)
            end_column = start_line + len(package)

    return {
        "startLine": start_line,
        "endLine": start_line,
        "startColumn": start_column,
        "endColumn": end_column,
    }


def report_npm_verify_sarif(package_path: str, rule_names: list[str], scan_results: list[dict]) -> str:
    rules = list(map(
        lambda s: get_rule(s),
        rule_names
    ))
    driver = get_driver(rules)
    results = []

    with open(package_path, "r") as file:
        package_raw = file.read()

    for entry in scan_results:
        if entry["result"]["issues"] == 0:
            continue
        region = _get_npm_region(package_raw, entry["dependency"])
        physical_location = get_physical_location(package_path, region)
        location = get_location(physical_location)
        scan_result_details = entry["result"]["results"]
        for rule_name in scan_result_details.keys():
            if len(scan_result_details[rule_name]) == 0:
                continue
            text = json.dumps(scan_result_details[rule_name], indent=2)
            key = f"{rule_name}-{text}"
            partial_fingerprints = {
                f"guarddog/v1/{rule_name}": hashlib.sha256(key.encode('utf-8')).hexdigest()
            }
            result = get_result(rule_name,
                                [location],
                                json.dumps(scan_result_details[rule_name], indent=2),
                                partial_fingerprints)
            results.append(result)

    runs = get_run(results, driver)
    log = get_sarif_log([runs])
    return json.dumps(log, indent=2)
