import os
from pathlib import Path

from semgrep.semgrep_main import invoke_semgrep


def analyze(path, rules=None) -> dict[str]:
    TARGET_PATH = [Path(path)]
    RULES_PATH = os.path.join(os.path.dirname(__file__), "semgrep")
    RULESET = [rule.replace(".yml", "") for rule in os.listdir(RULES_PATH)]
    
    if rules is None:
        return get_results(RULESET, RULES_PATH, TARGET_PATH, RULESET)
    
    return get_results(rules, RULES_PATH, TARGET_PATH, RULESET)

def get_results(rules, rulespath, targetpath, allrules):
    results = {rule: {} for rule in rules}
    
    if rules == allrules:
        response = invoke_semgrep(Path(os.path.join(rulespath)), targetpath)
        return results | format_response(response)
    
    for rule in rules:
        if rule not in allrules:
            raise RuntimeError(rule + " is not an existing rule.")
        
        response = invoke_semgrep(Path(os.path.join(rulespath, rule + ".yml")), targetpath)
        results = results | format_response(response, rule)

    return results

def format_response(response, rule=None):
    results = {}
    
    for result in response["results"]:
        label = rule or result["check_id"].split(".")[-1]
        
        message = result["extra"]["message"]
        file = result["path"]
        
        if label not in results:
            results[label] = {file: [message]}
        else:
            if file not in results[label]:
                results[label][file] = [message]
            else:
                results[label][file].append(message)

    return results