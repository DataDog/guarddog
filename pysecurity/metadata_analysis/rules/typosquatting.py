""" Typosquatting Detector

Detects if a package name is a typosquat of one of the top 1000 packages.
Checks for distance one Levenshtein, one-off character swaps, permutations
around hyphens, and substrings.
"""

from itertools import permutations

import requests


class TyposquatDetector:
    def __init__(self) -> None:
        num_packages = 5000
        popular_packages_url = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
        top_package_information = requests.get(popular_packages_url).json()["rows"][:num_packages]
        
        self.popular_packages = []
        self.lowercase_popular_packages = None
        
        for package in top_package_information:
            self.popular_packages.append(package["project"])
        
        self.lowercase_popular_packages = {package.lower(): package for package in self.popular_packages}
            
            
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
            if permutation in self.lowercase_popular_packages:
                similar.append(self.lowercase_popular_packages[permutation])
        
        return similar
    
    
    def _is_length_one_edit_away(self, package1, package2) -> bool:
        return (self._is_distance_one_Levenshtein(package1, package2) 
                or self._is_swapped_typo(package1, package2))
                
                
    def get_typosquatted_package(self, package_name) -> str:
        typosquatted = []
        
        lowercase_package = package_name.lower()
        py_swapped_package = None
        
        # Detect swaps like python-package -> py-package
        if "python" in lowercase_package:
            py_swapped_package = lowercase_package.replace("python", "py")
            typosquatted.extend(self._get_permuted_typosquats(py_swapped_package))
        elif "py" in lowercase_package:
            py_swapped_package = lowercase_package.replace("py", "python")
            typosquatted.extend(self._get_permuted_typosquats(py_swapped_package))
        
        typosquatted.extend(self._get_permuted_typosquats(lowercase_package))
        
        # Go through popular packages and find length one edit typosquats
        for popular_package in self.popular_packages:
            lowercase_popular_package = popular_package.lower()
            
            if package_name == popular_package:
                return []
                
            if self._is_length_one_edit_away(lowercase_package, lowercase_popular_package):
                typosquatted.append(popular_package)
                
            if py_swapped_package and self._is_length_one_edit_away(py_swapped_package, lowercase_popular_package):
                typosquatted.append(popular_package)
            
        return typosquatted
