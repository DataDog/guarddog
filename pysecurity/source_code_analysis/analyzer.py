import os
from pathlib import Path

from semgrep.semgrep_main import invoke_semgrep

IGNORE = [
    "helm",
    "venv",
    "test",
    "tests",
    ".env",
    "dist",
    "build",
    "semgrep",
    "migrations",
    ".github",
    ".semgrep_logs"
]

RULES_PATH = os.path.join(os.path.dirname(__file__), "semgrep")
RULESET = [rule.replace(".yml", "") for rule in os.listdir(RULES_PATH)]

def analyze(path, rules=None, prefix=None) -> dict[str]:  
    target_path = [Path(path)]
    
    if rules is None:
        return get_results(RULESET, RULES_PATH, target_path, prefix)
    
    return get_results(rules, RULES_PATH, target_path, prefix)

def get_results(rules, rulespath, targetpath, prefix=None):
    results = {rule: {} for rule in rules}
    
    if rules is None:
        response = invoke_semgrep(Path(os.path.join(rulespath)), targetpath, exclude = IGNORE)
        return results | format_response(response, prefix=prefix)
    
    for rule in rules:
        try:
            response = invoke_semgrep(Path(os.path.join(rulespath, rule + ".yml")), targetpath, exclude = IGNORE)
            results = results | format_response(response, rule=rule, prefix=prefix)
        except:
            raise RuntimeError(rule + " is not an existing rule.")
        
    return results

def format_response(response, rule=None, prefix=None):
    results = {}
    
    for result in response["results"]:
        label = rule or result["check_id"].split(".")[-1]
        
        message = result["extra"]["lines"]
        file = os.path.abspath(result["path"])
        
        if prefix:
            file = os.path.relpath(file, prefix)
            
        if label not in results:
            results[label] = {file: [message]}
        else:
            if file not in results[label]:
                results[label][file] = [message]
            else:
                results[label][file].append(message)

    return results