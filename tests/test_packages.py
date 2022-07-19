""" Tests rules against real examples of malware and nonmalware
"""

import json
import os
import pprint
import shutil
import sys
import zipfile

from pysecurity.cli import analyze_package


class MetricGenerator:
    def __init__(self) -> None:
        self.benign_logs_name = "benign_logs.json"
        self.malicious_logs_name = "malicious_logs.json"
        
        self.dirname = os.path.dirname(__file__)
        self.benign_path = os.path.join("./packages/benign")
        self.malicious_path = os.path.join("./packages/malicious")
        self.malicious_ground_truth_path = os.path.join(self.dirname, "malicious_ground_truth.json")
        
        # Find rules
        self.source_code_rulespath = os.path.join("./pysecurity/source_code_analysis/semgrep")
        self.source_code_rules = set(rule.replace(".yml", "") for rule in os.listdir(self.source_code_rulespath))
        
        self.metadata_rulespath = os.path.join("./pysecurity/metadata_analysis/rules")
        self.metadata_rules = set(rule.replace(".py", "") for rule in os.listdir(self.metadata_rulespath))
        
        self.all_rules = self.source_code_rules | self.metadata_rules
        
        # Populate malicious and benign results
        self.logs = {
            self.malicious_logs_name: self._populate_results(self.malicious_logs_name, self.malicious_path),
            self.benign_logs_name: self._populate_results(self.benign_logs_name, self.benign_path)
        }
    
    def _populate_results(self, log_name, path):
        if log_name in os.listdir(self.dirname):
            file = open(os.path.join(self.dirname, log_name))
            try:
                return json.load(file)
            except ValueError:
                return {}
        else:
            print("Log files not detected, scanning packages")
            return self._scan_packages(log_name, path)
                
    def _scan_packages(self, log_name, path, rules=None, start=0, end=None):
        packages = list(filter(lambda p: os.path.isdir(os.path.join(path, p)), os.listdir(path)))
        scan_results = {}
        
        if end is None:
            end = len(packages)
        
        for i in range(start, end):
            package_results = analyze_package(path, packages[i], rules)
            scan_results[packages[i]] = json.loads(package_results)
        
            print(packages[i])
            print(package_results)
            print()
        
        with open(os.path.join(self.dirname, log_name), "w+") as f:
            json.dump(scan_results, f, ensure_ascii=False, indent=4)
        
        return scan_results
            
    def scan(self, mode, rules=None, start=0, end=None):
        match mode:
            case "malicious":
                zipped_malicious_folder_path = os.path.join(self.malicious_path, "malware.zip") 
                zipped_malicious_folder = zipfile.ZipFile(zipped_malicious_folder_path)
                zipped_malicious_folder.extractall(self.malicious_path, pwd=b'infected')
                
                malware_path = os.path.join(self.malicious_path, "malware")
                self.logs[self.malicious_logs_name] = self._scan_packages(self.malicious_logs_name, 
                                                                            malware_path,
                                                                            rules, 
                                                                            start, 
                                                                            end)
                
                shutil.rmtree(malware_path)
            case "benign":
                self.logs[self.benign_logs_name] = self._scan_packages(self.benign_logs_name, 
                                                                          self.benign_path, 
                                                                          rules, 
                                                                          start, 
                                                                          end)
            case _:
                raise Exception("Unknown mode: " + mode)
            
    def test_benign(self): 
        false_negatives = {rule: {} for rule in self.all_rules}
        false_negative_count = {rule: 0 for rule in self.all_rules}
        
        for package, response in self.logs[self.benign_logs_name].items():
        
            assert set(response.keys()) == self.all_rules
            
            for rule, result in response.items():
            
                if (rule in self.source_code_rules and result != {} 
                    or rule in self.metadata_rules and result != []
                    ):
                    
                    false_negatives[rule][package] = result
                    false_negative_count[rule] += 1
        
        return false_negatives, false_negative_count


    def test_malicious(self):
        # Get actual and expected results
        self._populate_results(self.malicious_logs_name, self.malicious_path)
        
        ground_truth = None
        with open(self.malicious_ground_truth_path, "r") as f:
            ground_truth = json.load(f)
        
        # locations of FP,TP,FN
        false_positives = {rule: {} for rule in self.all_rules}
        true_positives = {rule: {} for rule in self.all_rules}
        false_negatives = {rule: {} for rule in self.all_rules}
        
        # counts of FP,TP,TN
        false_positive_count = {rule: 0 for rule in self.all_rules}
        true_positive_count = {rule: 0 for rule in self.all_rules}
        false_negative_count = {rule: 0 for rule in self.all_rules}
        
        for package, expected_results in ground_truth.items():
            
            assert set(expected_results.keys()) == self.all_rules
            
            for rule, expected_rule_result in expected_results.items():
                log_rule_result = self.logs[self.malicious_logs_name][package][rule]
                
                if rule in self.source_code_rules:
                    actual = set(log_rule_result.keys())
                    expected = set(expected_rule_result)
                elif rule in self.all_rules:
                    actual = set(log_rule_result)
                    expected = set(expected_rule_result)
                else:
                    raise Exception(rule + " not recognized")
                
                # calculate FP,TP,FN
                rule_false_positives = actual - expected
                rule_true_positives = expected & actual
                rule_false_negatives = expected - actual
                
                # update count and collection
                false_positive_count[rule] += len(rule_false_positives)
                true_positive_count[rule] += len(rule_true_positives)
                false_negative_count[rule] += len(rule_false_negatives)
                
                false_positives[rule][package] = rule_false_positives
                true_positives[rule][package] = rule_true_positives
                false_negatives[rule][package] = rule_false_negatives
        
        return ((false_positives, true_positives, false_negatives), 
                (false_positive_count, true_positive_count, false_negative_count))
        
    
    def get_precision_and_recall(self):
        malicious_fp, malicious_tp, malicious_fn = self.test_malicious()[1]
        benign_fp = self.test_benign()[1]
        
        false_positives = {rule: malicious_fp[rule] + benign_fp[rule] for rule in self.all_rules}
        
        precision = dict()
        recall = dict()
        
        for rule in self.all_rules:
            # Precision = TP/(TP+FP)
            precision[rule] = malicious_tp[rule]/(malicious_tp[rule] + false_positives[rule])
            
            # Recall = TP(TP+FN)
            recall[rule] = malicious_tp[rule]/(malicious_tp[rule] + malicious_fn[rule])
        
        return precision, recall
                
                

if __name__ == "__main__":
    metric_generator = MetricGenerator()
    
    result = metric_generator.get_precision_and_recall()
    pprint.pprint(result)