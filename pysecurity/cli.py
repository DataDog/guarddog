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


def main():
    """Entry point for pysecurity cli"""

    parsed_args = get_args()
    name = parsed_args.name
    version = parsed_args.version

    try:
        with tempfile.TemporaryDirectory() as tmpdirname:
            package_urls = get_package_urls(name, version)
            package_url = package_urls[0]
            response = requests.get(package_url, stream=True)

            if response.status_code == 200:
                path = os.path.dirname(os.path.abspath(__file__))
                dirname = os.path.join(path, tmpdirname + "/" + name + "-" + version)

                with open(dirname + ".tar.gz", "wb") as f:
                    f.write(response.raw.read())

                file = tarfile.open(dirname + ".tar.gz")
                file.extractall(dirname)
                file.close()

                typosquat_detector = TyposquatDetector()
                typosquat_results = typosquat_detector.get_typosquatted_package(name)

                if typosquat_results is not None:
                    print(typosquat_results)

                print(
                    invoke_semgrep(
                        Path(path + "/source_code_analysis/semgrep"), [Path(dirname)]
                    )
                )
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
    parser.add_argument(
        "-r", "--rules", help="Scanning heuristics", nargs="+", required=True
    )

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
