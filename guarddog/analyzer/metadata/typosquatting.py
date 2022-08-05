""" Typosquatting Detector

Detects if a package name is a typosquat of one of the top 1000 packages.
Checks for distance one Levenshtein, one-off character swaps, permutations
around hyphens, and substrings.
"""

import json
import os
from datetime import datetime, timedelta
from itertools import permutations

import requests

from pysecurity.analyzer.metadata.detector import Detector


class TyposquatDetector(Detector):
    def __init__(self) -> None:
        num_packages = 5000
        popular_packages_url = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
        
        # Fine top PyPI packages
        top_packages_filename = "top_pypi_packages.json"
        resourcesdir = os.path.abspath(os.path.join(os.path.dirname(__file__), "resources"))
        top_packages_path = os.path.join(resourcesdir, top_packages_filename)
        
        top_package_information = None
        
        if top_packages_filename in os.listdir(resourcesdir):
            update_time = datetime.fromtimestamp(os.path.getmtime(top_packages_path))
            
            if datetime.now()-update_time <= timedelta(days=30):
                top_packages_file = open(top_packages_path, "r")
                top_package_information = json.load(top_packages_file)["rows"][:num_packages]
            
        if top_package_information is None:           
            response = requests.get(popular_packages_url).json()
            with open(top_packages_path, "w+") as f:
                json.dump(response, f, ensure_ascii=False, indent=4)
                
            top_package_information = response["rows"][:num_packages]
        
        # Get list of popular packages
        self.popular_packages = []
        
        for package in top_package_information:
            name = package["project"]
            normalized_name = name.lower().replace('_', '-')
            self.popular_packages.append(normalized_name)
        
        super(Detector)
            
            
    def _is_distance_one_Levenshtein(self, name1, name2) -> bool:
        if abs(len(name1) - len(name2)) > 1:
            return False
        
        # Addition to name2
        if len(name1) > len(name2):
            for i in range(len(name1)):
                if name1[:i] + name1[i+1:] == name2:
                    return True
                
        # Addition to name1
        elif len(name2) > len(name1):
            for i in range(len(name2)):
                if name2[:i] + name2[i+1:] == name1:
                    return True  
        
        # Edit character
        else:
            for i in range(len(name1)):
                if name1[:i] + name1[i+1:] == name2[:i] + name2[i+1:]:
                    return True  
        
        return False


    def _is_swapped_typo(self, name1, name2) -> bool:
        if len(name1) == len(name2):
            for i in range(len(name1) - 1):
                swapped_name1 = name1[:i] + name1[i+1] + name1[i] + name1[i+2:]
                if swapped_name1 == name2:
                    return True
                
        return False


    def _generate_permutations(self, package_name) -> list[str]:
        if "-" not in package_name:
            return []
        
        components = package_name.split("-")
        hyphen_permutations = ["-".join(p) for p in permutations(components)]
        
        return hyphen_permutations
        
        
    def _get_permuted_typosquats(self, package) -> list[str]:
        similar = []
        for permutation in self._generate_permutations(package):
            if permutation in self.popular_packages and permutation != package:
                similar.append(permutation)
        
        return similar
    
    
    def _is_length_one_edit_away(self, package1, package2) -> bool:
        return (self._is_distance_one_Levenshtein(package1, package2) 
                or self._is_swapped_typo(package1, package2))
                
                
    def get_typosquatted_package(self, package_name) -> list[str]:
        typosquatted = []
        
        normalized_name = package_name.lower().replace('_', '-')
        py_swapped_package = None
        
        # Detect swaps like python-package -> py-package
        if "python" in normalized_name:
            py_swapped_package = normalized_name.replace("python", "py")
            typosquatted.extend(self._get_permuted_typosquats(py_swapped_package))
        elif "py" in normalized_name:
            py_swapped_package = normalized_name.replace("py", "python")
            typosquatted.extend(self._get_permuted_typosquats(py_swapped_package))
        
        typosquatted.extend(self._get_permuted_typosquats(normalized_name))
        
        # Go through popular packages and find length one edit typosquats
        for popular_package in self.popular_packages:
            normalized_popular_package = popular_package.lower().replace('_', '-')
            
            if normalized_name == popular_package:
                return []
                
            if self._is_length_one_edit_away(normalized_name, normalized_popular_package):
                typosquatted.append(popular_package)
                
            if py_swapped_package and self._is_length_one_edit_away(py_swapped_package, normalized_popular_package):
                typosquatted.append(popular_package)
            
        return typosquatted


    def detect(self, package_info) -> list[str]:
        return self.get_typosquatted_package(package_info["info"]["name"])
