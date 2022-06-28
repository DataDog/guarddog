""" PyPI Package Malware Scanner

CLI command that scans a PyPI package version for user-specified malware flags. 
Includes rules based on package registry metadata and source code analysis.

Example: 
    python3 scan.py -n requests -v 2.28.0 -r 0 2 5 6
"""

import argparse
import tempfile
import os
import requests
import tarfile

from semgrep.semgrep_main import invoke_semgrep
from pathlib import Path

cwd = os.getcwd()
parser = argparse.ArgumentParser()

parser.add_argument("-n", "--name", help="Package name", type=str, required=True)
parser.add_argument("-v", "--version", help="Package version", required=True)
parser.add_argument("-r", "--rules", help="Scanning heuristics", nargs="+", required=True)

args = parser.parse_args()


def get_package_urls(package_name, version):
    """Gets the download links for all PyPI distributions of a package and version

    Args:
        package_name (str): name of the package
        version (str): version of the package

    Raises:
        Exception: "Version " + version + " for package " + package_name + " doesn't exist."

    Returns:
        list<str>: list of all download urls
    """
    
    url = "https://pypi.org/pypi/%s/json" % (package_name,)
    data = requests.get(url).json()
    releases = data["releases"]
    
    if version in releases:
        files = releases[version]
        urls = []
        
        for file in files:
            if file["filename"].endswith(".tar.gz"):
                urls.append(file["url"])
                
        return urls
    
    else:
        raise Exception("Version " + version + " for package " + package_name + " doesn't exist.")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmpdirname:
        package_urls = get_package_urls(args.name, args.version)
        package_url = package_urls[0]
        response = requests.get(package_url, stream=True)
        
        if response.status_code == 200:
            filename = tmpdirname + "/" + args.name + "-" + args.version
            
            with open(filename +  ".tar.gz", 'wb') as f:
                f.write(response.raw.read())
            
            file = tarfile.open(filename + ".tar.gz")
            file.extractall(filename)
            file.close()
            
            print(invoke_semgrep(Path("rules/semgrep"), [Path(filename)]))
        else:
            raise Exception("Received: " + response.status_code)

