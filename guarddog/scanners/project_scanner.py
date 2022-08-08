import functools
import os
import re
import sys
from pprint import pprint

import pathos
import pkg_resources
import requests

from guarddog.scanners.package_scanner import PackageScanner
from guarddog.scanners.scanner import Scanner


class RequirementsScanner(Scanner):
    def __init__(self) -> None:
        self.package_scanner = PackageScanner()
        super(Scanner)

    
    def _authenticate_by_access_token(self):
        user = os.getenv('GIT_USERNAME')
        personal_access_token = os.getenv('GH_TOKEN')
        if user == None or personal_access_token == None:
            print("WARNING: Please set GIT_USERNAME (Github handle) and GH_TOKEN (generate a personal access token in Github settings > developer) as environment variables before proceeding.")
            exit(1)
        return (user, personal_access_token)
    
    
    def sanitize_requirements(self, requirements):
        sanitized_lines = []
        
        for line in requirements:
            stripped_line = line.strip()
            
            is_requirement = re.match(r'\w', stripped_line) and len(stripped_line) > 0
            if is_requirement:
                sanitized_lines.append(stripped_line)
            
        return sanitized_lines
        
    
    def parse_requirements(self, requirements):
        
        def versions(package_name):
            url = "https://pypi.org/pypi/%s/json" % (package_name,)
            data = requests.get(url).json()
            versions = sorted(data["releases"].keys(), reverse=True)
            return versions
        
        sanitized_requirements = self.sanitize_requirements(requirements)
        
        dependencies = {}
        
        try:
            for requirement in pkg_resources.parse_requirements(sanitized_requirements):
                valid_versions = None
                for spec in requirement.specs:
                    qualifier, version = spec
                    
                    try:
                        available_versions = versions(requirement.project_name)
                    except Exception as e:
                        sys.stderr.write(f"Package {requirement.project_name} not on PyPI")
                        continue
                    
                    used_versions = None
                    
                    match qualifier:
                        case ">":
                            used_versions = {v for v in available_versions if v > version}
                        case "<":
                            used_versions = {v for v in available_versions if v < version}
                        case ">=":
                            used_versions = {v for v in available_versions if v >= version}
                        case "<=":
                            used_versions = {v for v in available_versions if v <= version}
                        case "==":
                            matching_versions = filter(lambda v: v is not None, (re.search(version, candidate) for candidate in available_versions))
                            matching_versions = set(match.string for match in matching_versions)
                            used_versions = matching_versions
                        case "~=":
                            prefix = "".join(version.split(".")[:-1])
                            for available_version in available_versions: # sorted decreasing
                                if available_version >= version and available_version.startswith(prefix):
                                    used_versions = set(available_version)
                                    break
                        case _:
                            sys.stderr.write(f"Unknown qualifier: {qualifier}")
                            continue
                        
                    if valid_versions is None:
                        valid_versions = used_versions
                    else:
                        valid_versions = valid_versions & used_versions

                dependencies[requirement.project_name] = valid_versions
        except Exception as e:
            sys.stderr.write(f"Received error {str(e)}")

        return dependencies
    
    
    def scan_requirements(self, requirements, quiet=False):
        """
        Reads the requirements.txt file and outputs valid dependencies and versions
        """
        
        def get_package_results_helper(dependency, version, quiet):
            result = self.package_scanner.scan_remote(dependency, version)
            
            if not quiet:
                sys.stdout.write(f"\n {dependency}/{version} \n")
                pprint(result) 
        
        get_package_results = functools.partial(get_package_results_helper, quiet=quiet)
        dependencies = self.parse_requirements(requirements)
        
        params = []
        for dependency, versions in dependencies.items():
            for version in versions:
                params.append((dependency, version))
                
        pool = pathos.helpers.mp.Pool()
        project_results = pool.starmap(get_package_results, params)
        
        return project_results
    
    
    def scan_local(self, path, quiet=False):
        try:
            with open(path, "r") as f:
                return self.scan_requirements(f.readlines(), quiet)
        except Exception as e:
            sys.stdout.write(f"Received {e}")
            sys.exit(255)


    def scan_remote(self, url, branch, quiet=False, requirements_name="requirements.txt"):
        token = self._authenticate_by_access_token()
        githubusercontent_url = url.replace("github", "raw.githubusercontent")
        
        req_url = f"{githubusercontent_url}/{branch}/{requirements_name}"
        resp = requests.get(url=req_url, auth=token)
        
        if resp.status_code == 200:
            return self.scan_requirements(resp.content.decode().splitlines(), quiet)
        else:
            sys.stdout.write(f"{req_url} does not exist. Check your link or branch name.")
            sys.exit(255)