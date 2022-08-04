""" Tests rules against real examples of malware and nonmalware
"""

import json
import os
import pprint
import shutil
import sys
import zipfile
from pathlib import Path

import requests
from tqdm.auto import tqdm

from pysecurity.analyzer.analyzer import Analyzer
from pysecurity.scanners.package_scanner import PackageScanner


class Evaluator:
    """ Generates accuracy metrics of pysecurity tool by running against real malware.

        Evaluates the CLI tool by:
        1. Scanning benign packages (top 1000 downloaded packages on PyPI) and malicious packages.
        2. Recording the scan results in logs directory.
        3. Evaluating scan results with (TP, FP, FN)
        4. From metrics, give accuracy results such as precision, recall, false positive rate, etc.
    """
    
    def __init__(self) -> None:
        # Analyzer to scan packages
        self.analyzer = Analyzer()
        self.package_scanner = PackageScanner() # to download packages
        
        # Relevant paths
        self.project_root = Path(__file__).parents[1] # get grandparent
        self.dirname = Path(os.path.dirname(__file__))
        
        # Data paths
        self.benign_path = self.dirname.joinpath(Path("data/benign"))
        self.malicious_path = self.dirname.joinpath(Path("data/malicious"))
        
        # Logs paths and size
        self.benign_size = 1000
        
        self.benign_logs_name = "benign_logs.json"
        self.malicious_logs_name = "malicious_logs.json"
        self.malicious_ground_truth_name = "malicious_ground_truth.json"
        self.logs_path = self.dirname.joinpath(Path("logs"))
        
        # Find rules
        self._get_rules()
        
        # Populate malicious and benign results
        self.logs = {
            self.malicious_logs_name: self._populate_results(self.malicious_logs_name, self.malicious_path),
            self.benign_logs_name: self._populate_results(self.benign_logs_name, self.benign_path)
        }
        
        # Metrics (TP, FP, FN)
        self.false_positive_rate = {rule: None for rule in self.all_rules}
        
        self.metrics = {
            "true_positives": {},
            "false_positives": {},
            "false_negatives": {}
        }
        
        for rule in self.all_rules:
            for _, result in self.metrics.items():
                result[rule] = 0
            
        
    def _get_rules(self) -> None:
        """ Gets the source code analysis and metadata analysis rules
        """
        
        self.source_code_rules = self.analyzer.sourcecode_ruleset
        self.metadata_rules = self.analyzer.metadata_ruleset
        
        self.all_rules = self.source_code_rules | self.metadata_rules
        
        
    def _download_benign(self) -> None:
        """ Downloads most popular packages as benign data
        """
        
        popular_packages_url = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
        top_packages = requests.get(popular_packages_url).json()["rows"][:self.benign_size]
        progress_bar = tqdm(total=self.benign_size)
        progress_bar.set_description("Downloading benign packages")
        
        for package in top_packages:
            name = package["project"]
            self.package_scanner.download_package(name, self.benign_path)
            progress_bar.update(1)
            
        progress_bar.close()
            

    def _populate_results(self, log_name, path) -> dict:
        """ Fetches preexisting log data

        Args:
            log_name (str): Name of log file
            path (str): Path to log file

        Returns:
            dict: Log data
        """
        
        if log_name in os.listdir(self.logs_path):
            file = open(self.logs_path.joinpath(log_name))
            try:
                return json.load(file)
            except ValueError:
                return {}
        else:
            print("Log files not detected, scanning packages")
            return self._scan_packages(log_name, path)


    def _scan_packages(self, log_name, path, rules=None) -> None:
        """ Scans packages in path and records results to log_name

        Args:
            log_name (str): Name of logs to record results to
            path (str): Path to scan
            rules (list[str], optional): Rules to scan. If none, 
                uses all possible rules. Defaults to None.
        """
        
        package_names = list(filter(lambda p: os.path.isdir(os.path.join(path, p)), os.listdir(path)))
        scan_results = {}
        
        progress_bar = tqdm(total=len(package_names), position=0, leave=True)
        progress_bar.set_description("Scanning packages")
        
        # Scan packages
        for name in package_names:
            package_path = os.path.join(path, name)
            package_info = {"info": {"name": name}}
            package_results = self.analyzer.analyze(package_path, package_info, rules)["results"]
            scan_results[name] = package_results
        
            progress_bar.update()
        
        # Record results in log
        with open(self.logs_path.joinpath(log_name), "w+") as f:
            json.dump(scan_results, f, ensure_ascii=False, indent=4)
        
        progress_bar.close()

        return scan_results


    def scan(self, rules=None) -> None:
        """ Scans the malicious and benign data using pysecurity

        Args:
            rules (set[str], optional): Rules used when scanning. Defaults to None.
        """
        
        # Scan malicious data
        zipped_malicious_folder_path = self.malicious_path.joinpath("malware.zip") 
        zipped_malicious_folder = zipfile.ZipFile(zipped_malicious_folder_path)
        zipped_malicious_folder.extractall(self.malicious_path, pwd=b'infected')
        
        malware_path = os.path.join(self.malicious_path, "malware")
        
        self.logs[self.malicious_logs_name] = self._scan_packages(
            self.malicious_logs_name, 
            malware_path,
            rules)
        
        shutil.rmtree(malware_path) # remove zip folder after extracted
        
        # Scan benign data
        if len(os.listdir(self.benign_path)) == 0:
            self._download_benign()
            
        self.logs[self.benign_logs_name] = self._scan_packages(
            self.benign_logs_name, 
            self.benign_path, 
            rules)


    def _evaluate_benign(self, show=False) -> None: 
        """ Evaluates the benign data using available log files.
            Finds the false positive and true negative rates.

        Args:
            show (bool, optional): Flag to show incorrect results. Defaults to False.
        """
        
        num_packages = len(list(filter(lambda p: os.path.isdir(os.path.join(self.benign_path, p)), 
                                       os.listdir(self.benign_path))))
        
        file_false_positive_count = {rule: 0 for rule in self.all_rules}
        package_false_positive_count = {rule: 0 for rule in self.all_rules}
        
        if show:
            sys.stdout.write("Evaluating incorrect answers in benign data\n")
            
        for package, response in self.logs[self.benign_logs_name].items():
            
            for rule, result in response.items():
            
                if (rule in self.source_code_rules and result != {} 
                    or rule in self.metadata_rules and result
                    ):
                    
                    if show:
                        incorrect_warning = set(result.keys()) if type(result) is dict else result
                        sys.stdout.write("-" + package + "/" + rule + ": " + str(incorrect_warning))
                        sys.stdout.write("\n")
                        
                    file_false_positive_count[rule] += len(result)
                    package_false_positive_count[rule] += 1
                    
        if show:
            sys.stdout.write("\n")
            
        for rule in self.all_rules:
            self.metrics["false_positives"][rule] += file_false_positive_count[rule]
            self.false_positive_rate[rule] = package_false_positive_count[rule] / num_packages


    def _evaluate_malicious(self, show=False) -> None:
        """ Evaluates the malicious data using available log files.
            Finds the false positive, true positive, and false negative rates.

        Args:
            show (bool, optional): Flag to show incorrect results. Defaults to False.
        """
        
        metric_names = ["false_positives", "true_positives", "false_negatives"]
        
        # Get actual and expected results
        self._populate_results(self.malicious_logs_name, self.malicious_path)
        
        ground_truth = None
        with open(self.logs_path.joinpath(self.malicious_ground_truth_name), "r") as f:
            ground_truth = json.load(f)
        
        # counts of FP,TP,FN
        metric_counts = {}
        
        for metric in metric_names:
            metric_counts[metric] = {rule: 0 for rule in self.all_rules}
        
        if show:
            sys.stdout.write("Evaluating incorrect answers in malicious data:\n")
            
        # calculate metrics and metric counts
        for package, expected_results in ground_truth.items():
            
            for rule, expected_rule_result in expected_results.items():
                log_rule_result = self.logs[self.malicious_logs_name][package][rule]
                
                actual = set(log_rule_result)
                expected = set(expected_rule_result)
                
                # calculate FP,TP,FN
                rule_metrics = {
                    "false_positives": actual - expected,
                    "true_positives": expected & actual,
                    "false_negatives": expected - actual
                }
                
                if show and actual != expected:
                    sys.stdout.write("-" + package + "/" + rule + ": " + str(actual) + ", " + str(expected))
                    sys.stdout.write("\n")
                
                # update count and collection
                for metric in metric_names:
                    metric_counts[metric][rule] += len(rule_metrics[metric])
            
        for metric in metric_names:
            for rule, count in self.metrics[metric].items():
                self.metrics[metric][rule] = count + metric_counts[metric][rule]
        
        if show:
            sys.stdout.write("\n")


    def evaluate(self, show=False) -> None:
        """ Evaluates benign and malicious data
            by calculating false positives, true postives,
            false negatives, and true negatives
        """
        
        self._evaluate_benign(show=show)
        self._evaluate_malicious(show=show)
        
        
    def get_precision_and_recall(self) -> tuple[dict[str, float], dict[str, float]]:
        """ Gets the precision and recall per rule after scanning log files

        Returns:
            tuple[dict[str, float], dict[str, float]]: (precision per rule, recall per rule)
        """
        
        precision = dict()
        recall = dict()
        
        for rule in self.all_rules:
            true_positives = self.metrics["true_positives"][rule]
            false_positives = self.metrics["false_positives"][rule]
            false_negatives = self.metrics["false_negatives"][rule]
            
            try:
                # Precision = TP/(TP+FP)
                precision[rule] = true_positives/(true_positives + false_positives)
                
                # Recall = TP(TP+FN)
                recall[rule] = true_positives/(true_positives + false_negatives)
            except ZeroDivisionError as e:
                print("Not enough data for " + rule, file=sys.stderr)
        
        return precision, recall
    
    def get_false_positive_rate(self) -> dict[str, float]:
        """ Gets the false positive rate of the tool

        Returns:
            dict[str, float]: false positive rate per rule
        """
        
        for _, value in self.false_positive_rate.items():
            if value is None:
                self._evaluate_benign()
                break
            
        return self.false_positive_rate
                
                

if __name__ == "__main__":
    metric_generator = Evaluator()
    # metric_generator.scan()
    metric_generator.evaluate(show=True)
    
    accuracy = metric_generator.get_precision_and_recall()
    false_positive_rate = metric_generator.get_false_positive_rate()
    
    # Display information
    sys.stdout.write("Precision, recall per rule:\n")
    pprint.pprint(accuracy)
    sys.stdout.write("\n")
    
    print("False positive rate per rule:\n")
    pprint.pprint(false_positive_rate)