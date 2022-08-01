import json
import os
import re
import sys
from posixpath import dirname

import pkg_resources
import requests
from tqdm import tqdm

from pysecurity.scanners.package_scanner import PackageScanner
from pysecurity.scanners.scanner import Scanner

BASE_URL = "https://api.github.com"
DATADOG_URL_SUFFIX = "orgs/DataDog/repos"
MAX_RESULTS_PER_PAGE = 100
SAVED_CACHE = dirname(__file__)


class RequirementsScanner(Scanner):
    def __init__(self) -> None:
        self.package_scanner = PackageScanner()
        super(Scanner)

    
    def authenticate_by_access_token(self):
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
            
            is_comment = stripped_line.startswith("#")
            is_install_line = stripped_line.startswith("--") or  stripped_line.startswith("-i")
            is_link = stripped_line.startswith("http") or stripped_line.startswith("git+")
            
            if not is_comment and not is_install_line and not is_link and len(line) > 0:
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
    
    
    def scan_requirements(self, requirements):
        # Read the requirements.txt file and output the dependencies and versions
        dependencies = self.parse_requirements(requirements)
        project_results = {}
        progressbar = tqdm(total=len(dependencies))
        
        for dependency, versions in dependencies.items():
            for version in versions:
                package_results = self.package_scanner.scan_remote(dependency, version)
                project_results[f"{dependency}/{version}"] = package_results
                progressbar.update(1)
            
        return project_results
    
    
    def scan_local(self, path, requirements_name="requirements.txt"):
        try:
            with open(os.path.join(path, requirements_name), "r") as f:
                return self.scan_requirements(f.readlines())
        except Exception as e:
            sys.stdout.write(f"Received {e}")
            sys.exit(255)


    def scan_remote(self, url, branch, requirements_name="requirements.txt"):
        token = self.authenticate_by_access_token()
        githubusercontent_url = url.replace("github", "raw.githubusercontent")
        
        req_url = f"{githubusercontent_url}/{branch}/{requirements_name}"
        resp = requests.get(url=req_url, auth=token)
        
        if resp.status_code == 200:
            return self.scan_requirements(resp.content.decode().splitlines())
        else:
            sys.stdout.write(f"{req_url} does not exist. Check your link or branch name.")
            sys.exit(255)