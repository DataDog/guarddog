""" PyPI Package Malware Scanner

CLI command that scans a PyPI package version for user-specified malware flags.
Includes rules based on package registry metadata and source code analysis.
"""

import json
import os
import re
from pprint import pprint

import click

from .analyzer.analyzer import Analyzer
from .scanners.package_scanner import PackageScanner
from .scanners.project_scanner import RequirementsScanner

analyzer = Analyzer()
ALL_RULES = analyzer.sourcecode_ruleset | analyzer.metadata_ruleset


@click.group
def cli():
    """Guard Dog cli tool to detect PyPI malware"""
    pass


@cli.command("verify")
@click.argument("path")
@click.option("-o", "--output-file", default=None, type=click.Path(exists=False))
@click.option("-q", "--quiet", default=False)
def verify(path, output_file, quiet):
    """Verify a requirements.txt file

    Args:
        path (str): path to requirements.txt file
        output_file (str): path to output file
    """
    scanner = RequirementsScanner()
    results = scanner.scan_local(path, quiet)

    if output_file:
        basedir = os.path.dirname(output_file)
        is_basedir_exist = os.path.exists(basedir)

        if not is_basedir_exist:
            os.makedirs(basedir)

        with open(output_file, "w+") as f:
            json.dump(results, f, ensure_ascii=False, indent=4)


@cli.command("scan")
@click.argument("identifier")
@click.option("-v", "--version", default=None, help="Specify a version to scan")
@click.option("-r", "--rules", multiple=True, type=click.Choice(ALL_RULES, case_sensitive=False))
def scan(identifier, version, rules):
    """Scan a package

    Args:
        identifier (str): name or path to the package
        version (str): version of the package (ex. 1.0.0), defaults to most recent
        rules (str): specific rules to run, defaults to all
    """

    rule_param = None
    if len(rules) != 0:
        rule_param = rules

    scanner = PackageScanner()
    results = {}
    if is_local_package(identifier):
        results = scanner.scan_local(identifier, rule_param)
    else:
        results = scanner.scan_remote(identifier, version, rule_param)

    pprint(results)

# Determines if the input passed to the 'scan' command is a local package name
def is_local_package(input):
    identifier_is_path = re.search(r"(.{0,2}\/)+.+", input)
    return identifier_is_path or input.endswith('.tar.gz')