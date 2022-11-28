""" PyPI Package Malware Scanner

CLI command that scans a PyPI package version for user-specified malware flags.
Includes rules based on package registry metadata and source code analysis.
"""

import re
import sys

import click
from termcolor import colored

from .analyzer.analyzer import Analyzer
from .scanners.package_scanner import PackageScanner
from .scanners.project_scanner import RequirementsScanner

analyzer = Analyzer()
ALL_RULES = analyzer.sourcecode_ruleset | analyzer.metadata_ruleset
EXIT_CODE_ISSUES_FOUND = 1

@click.group
def cli():
    """Guard Dog cli tool to detect PyPI malware"""
    pass


@cli.command("verify")
@click.argument("path")
@click.option("--json", default=False, is_flag=True, help="Dump the output as JSON to standard out")
@click.option("--exit-non-zero-on-finding", default=False, is_flag=True, help="Exit with a non-zero status code if at least one issue is identified")
def verify(path, json, exit_non_zero_on_finding):
    """Verify a requirements.txt file

    Args:
        path (str): path to requirements.txt file
    """
    scanner = RequirementsScanner()
    results = scanner.scan_local(path)
    for result in results:
        identifier = result['dependency'] if result['version'] is None else f"{result['dependency']} version {result['version']}"
        if not json:
            print_scan_results(result.get('result'), identifier)
    
    if json:
        import json as js
        print(js.dumps(results))

    if exit_non_zero_on_finding:
        exit_with_status_code(results)

@cli.command("scan")
@click.argument("identifier")
@click.option("-v", "--version", default=None, help="Specify a version to scan")
@click.option("-r", "--rules", multiple=True, type=click.Choice(ALL_RULES, case_sensitive=False))
@click.option("-x", "--exclude-rules", multiple=True, type=click.Choice(ALL_RULES, case_sensitive=False))
@click.option("--json", default=False, is_flag=True, help="Dump the output as JSON to standard out")
@click.option("--exit-non-zero-on-finding", default=False, is_flag=True, help="Exit with a non-zero status code if at least one issue is identified")
def scan(identifier, version, rules, exclude_rules, json, exit_non_zero_on_finding):
    """Scan a package

    Args:
        identifier (str): name or path to the package
        version (str): version of the package (ex. 1.0.0), defaults to most recent
        rules (str): specific rules to run, defaults to all
    """

    rule_param = None
    if len(rules) != 0:
        rule_param = rules
    if len(exclude_rules):
        rule_param = ALL_RULES - set(exclude_rules)

    scanner = PackageScanner()
    results = {}
    if is_local_package(identifier):
        results = scanner.scan_local(identifier, rule_param)
    else:
        try:
            results = scanner.scan_remote(identifier, version, rule_param)
        except Exception as e:
            sys.stderr.write("\n")
            sys.stderr.write(str(e))
            sys.exit()

    if json:
        import json as js
        print(js.dumps(results))
    else:
        print_scan_results(results, identifier)

    if exit_non_zero_on_finding:
        exit_with_status_code(results)

# Determines if the input passed to the 'scan' command is a local package name
def is_local_package(input):
    identifier_is_path = re.search(r"(.{0,2}\/)+.+", input)
    return identifier_is_path or input.endswith('.tar.gz')


# Pretty prints scan results for the console
def print_scan_results(results, identifier):
    num_issues = results.get('issues')

    if num_issues == 0:
        print("Found " + colored('0 potentially malicious indicators', 'green', attrs=['bold']) + " scanning " + colored(identifier, None, attrs=['bold']))
        print()
        return
    
    print("Found " + colored(str(num_issues) + ' potentially malicious indicators', 'red', attrs=['bold']) + " in " + colored(identifier, None, attrs=['bold']))
    print()
    
    results = results.get('results', [])
    for finding in results:
        description = results[finding]
        if type(description) == str: # package metadata
            print(colored(finding, None, attrs=['bold']) + ': ' + description)
            print()
        elif type(description) == list: # semgrep rule result:
            source_code_findings = description
            print(colored(finding, None, attrs=['bold']) + ': found ' + str(len(source_code_findings)) + ' source code matches')
            for finding in source_code_findings:
                print('  * ' + finding['message'] + ' at ' + finding['location'] + '\n    ' + format_code_line_for_output(finding['code']))
            print()


def format_code_line_for_output(code):
    return '    ' + colored(code.strip().replace('\n', '\n    ').replace('\t', '  '), None, 'on_red', attrs=['bold'])


# Given the results, exit with the appropriate status code
def exit_with_status_code(results):
    num_issues = results.get('issues', 0)
    if num_issues > 0:
        exit(EXIT_CODE_ISSUES_FOUND)