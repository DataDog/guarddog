import os
from pathlib import Path

from semgrep.semgrep_main import invoke_semgrep

EXCLUDE = [
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


def analyze(path, rules=None) -> dict[str]:  
    rulespath = os.path.join(os.path.dirname(__file__), "semgrep")
    ruleset = [rule.replace(".yml", "") for rule in os.listdir(rulespath)]
    targetpath = Path(path)
    
    results = {rule: {} for rule in (rules or ruleset)}
    
    if rules is None:
        response = invoke_semgrep(Path(rulespath), [targetpath], exclude = EXCLUDE)
        return results | format_response(response, targetpath=targetpath)
    
    for rule in rules:
        try:
            response = invoke_semgrep(Path(os.path.join(rulespath, rule + ".yml")), [targetpath], exclude = EXCLUDE, no_git_ignore=True)
            results = results | format_response(response, rule=rule, targetpath=targetpath)
        except:
            raise RuntimeError(rule + " is not an existing rule.")
        
    return results


def format_response(response, rule=None, targetpath=None):
    results = {}
    
    for result in response["results"]:
        label = rule or result["check_id"].split(".")[-1]
        
        message = result["extra"]["lines"]
        
        line_start = result["start"]["line"]
        file = os.path.abspath(result["path"])
        
        if targetpath:
            file = os.path.relpath(file, targetpath)
            
        location = file + ":" + str(line_start)
        
        if label not in results:
            results[label] = {location: message}
        else:
            results[label][location] = message

    return results