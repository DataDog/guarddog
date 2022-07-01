""" PyPI Package Malware Scanner

CLI command that scans a PyPI package version for user-specified malware flags. 
Includes rules based on package registry metadata and source code analysis.
"""

import argparse
import os
import signal
import sys
import tarfile
import tempfile
from pathlib import Path

import requests
from semgrep.semgrep_main import invoke_semgrep

from pysecurity.metadata_analysis.typosquatting import TyposquatDetector
from pysecurity.source_code_analysis.analyzer import analyze


def main():
    """Entry point for pysecurity cli"""

    parsed_args = get_args()
    name = parsed_args.name
    version = parsed_args.version
    rules = parsed_args.rules
    
    if os.path.exists(name):
        analyze_package(os.path.dirname(name), os.path.basename(name), rules)
        return
    
    try:
        with tempfile.TemporaryDirectory() as tmpdirname:
            package_urls = get_package_urls(name, version)
            package_url = package_urls[0]
            response = requests.get(package_url, stream=True)

            if response.status_code == 200:
                cwd = os.path.dirname(os.path.abspath(__file__))
                directory = os.path.join(cwd, tmpdirname)
                filename = name + "-" + version
                fullpath = os.path.join(directory, filename)
                
                with open(fullpath + ".tar.gz", "wb") as f:
                    f.write(response.raw.read())

                file = tarfile.open(fullpath + ".tar.gz")
                file.extractall(fullpath)
                file.close()

                analyze_package(directory, filename, rules)
            else:
                raise Exception("Received: " + response.status_code)
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
    parser.add_argument("-v", "--version", help="Package version", required=True)
    parser.add_argument( "-r", "--rules", help="Scanning heuristics", nargs="+")

    return parser


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
        raise Exception(
            "Version " + version + " for package " + package_name + " doesn't exist."
        )

def analyze_package(directory, name, rules):
    """Analyzes package in directory/name with the given rules

    Args:
        directory (str): path to package directory
        name (str): name of package directory
        rules (list(str)): list of rules to analyze package wtih
    """
    
    filename = os.path.join(directory, name)

    typosquat_detector = TyposquatDetector()
    typosquat_results = typosquat_detector.get_typosquatted_package(name)
    results = analyze(Path(filename), rules)
    results["typosquatting"] = typosquat_results
    
    print(results)