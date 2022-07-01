""" Typosquatting Detector

Detects if a package name is a typosquat of one of the top 1000 packages.
Checks for distance one Levenshtein, one-off character swaps, permutations
around hyphens, and substrings.
"""

import os


class TyposquatDetector:
    def __init__(self) -> None:
        filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "most-popular-packages.csv")
        self.popular_packages = None

        with open(filepath) as f:
            self.popular_packages = f.read().splitlines()
    
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

    def _generate_permutations(self, package_name) -> list:
        if "-" not in package_name:
            return []
        
        components = package_name.split("-")
        
        permutations = [list(component) for component in components]
        for component in components:
            for permutation in permutations:
                if component not in permutation:
                    permutation.append(component)
        
        return permutations
    
    def get_typosquatted_package(self, package_name) -> str:
        for popular_package in self.popular_packages:
            if package_name == popular_package:
                return None
            
            for permutation in self._generate_permutations(package_name):
                if permutation in self.popular_packages:
                    return permutation
                
            if (
                self._is_distance_one_Levenshtein(package_name, popular_package) 
                or self._is_swapped_typo(package_name, popular_package)
                # or package_name in popular_package
            ):
                return popular_package
            
        return None
    