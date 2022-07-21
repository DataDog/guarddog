""" PyPI Package Malware Scanner

CLI command that scans a PyPI package version for user-specified malware flags. 
Includes rules based on package registry metadata and source code analysis.
"""

import argparse
import json
import os
import shutil
import signal
import sys
import tempfile
from pathlib import Path

import requests

from pysecurity.metadata_analysis.rules.typosquatting import TyposquatDetector
from pysecurity.source_code_analysis.analyzer import analyze


def main():
    """Entry point for pysecurity cli"""

    parsed_args = get_args()
    name = parsed_args.name
    version = parsed_args.version
    rules = parsed_args.rules
    
    if rules is not None:
        rules = set(rules)
    
    if os.path.exists(name):
        return analyze_package(os.path.dirname(name), os.path.basename(name), rules)
    try:
        with tempfile.TemporaryDirectory() as tmpdirname:
            # Directory to download compressed and uncompressed package
            directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), tmpdirname)
            
            download_package(name, directory, version)
            return analyze_package(directory, name, rules)
    except KeyboardInterrupt:
        sys.stdout.write("\n")
        sys.stdout.write("KeyboardInterrupt detected.")
        return 128 + signal.SIGINT
    except Exception as e:
        sys.stderr.write("\n")
        sys.stderr.write(str(e))
        return 255


def get_args():
    """Returns arguments for cli command"""
    return get_parser().parse_args()


def get_parser():
    """Gets the parser for the cli arguments

    Returns:
        argparse.ArgumentParser: argument parser
    """
    parser = argparse.ArgumentParser()

    parser.add_argument("-n", "--name", help="Package name", type=str, required=True)
    parser.add_argument("-v", "--version", help="Package version")
    parser.add_argument( "-r", "--rules", help="Scanning heuristics", nargs="+")

    return parser


def download_package(package_name, directory, version=None):
    """Downloads the PyPI distribution for a given package and version

    Args:
        package_name (str): name of the package
        directory (str): directory to download package to
        version (str): version of the package

    Raises:
        Exception: "Received status code: " + <not 200> + " from PyPI"
        Exception: "Version " + version + " for package " + package_name + " doesn't exist."
        Exception: "Compressed file for package does not exist."
        Exception: "Error retrieving package: " + <error message>
    Returns:
        None
    """
    
    url = "https://pypi.org/pypi/%s/json" % (package_name,)
    response = requests.get(url)
    
    # Check if package file exists
    if response.status_code != 200:
        raise Exception("Received status code: " + str(response.status_code) + " from PyPI")
    
    data = response.json()
    
    # Check for error in retrieving package
    if "message" in data:
        raise Exception("Error retrieving package: " + data["message"])
    
    releases = data["releases"]
    
    if version is None:
        version = data['info']['version']
    
    if version in releases:
        files = releases[version]
        
        url = None
        file_extension = None
        
        for file in files:
            # Store url to compressed package and appropriate file extension
            if file["filename"].endswith(".tar.gz"):
                url = file["url"]
                file_extension = ".tar.gz"
                
            if (file["filename"].endswith(".egg") or 
                file["filename"].endswith(".whl") or 
                file["filename"].endswith(".zip")):
                    url = file["url"]
                    file_extension = ".zip"
        
        if url and file_extension:            
            response = requests.get(url, stream=True)
            
            # Paths to compressed and uncompressed package
            zippath = os.path.join(directory, package_name + file_extension)
            unzippedpath = os.path.join(directory, package_name)
            
            with open(zippath, "wb") as f:
                f.write(response.raw.read())

            shutil.unpack_archive(zippath, unzippedpath)
            os.remove(zippath)
        else:
            raise Exception("Compressed file for package does not exist.")
    else:
        raise Exception(
            "Version " + version + " for package " + package_name + " doesn't exist."
        )

def analyze_package(directory, name, rules=None):
    """Analyzes package in directory/name with the given rules

    Args:
        directory (str): path to package directory
        name (str): name of package directory
        rules (list(str)): list of rules to analyze package with
    
    Returns:
        json output of warnings in the form of:
            {
                <rule>: information about warning
                ...
            }
    """
    filename = os.path.join(directory, name)
    results = analyze(Path(filename), rules)
    
    if rules is None or "typosquatting" in rules:
        typosquat_detector = TyposquatDetector()
        typosquat_results = typosquat_detector.get_typosquatted_package(name)
        results["typosquatting"] = typosquat_results
    
    return json.dumps(results)