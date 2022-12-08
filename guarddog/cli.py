""" PyPI Package Malware Scanner

CLI command that scans a PyPI package version for user-specified malware flags.
Includes rules based on package registry metadata and source code analysis.
"""

import re
import sys
from typing import cast, Optional

import click
from termcolor import colored

from guarddog.analyzer.analyzer import SEMGREP_RULE_NAMES, METADATA_DETECTORS
from guarddog.ecosystems import ECOSYSTEM
from guarddog.scanners import get_scanner
from guarddog.scanners.scanner import PackageScanner

ALL_RULES = METADATA_DETECTORS.keys() | SEMGREP_RULE_NAMES
EXIT_CODE_ISSUES_FOUND = 1


def common_options(fn):
    fn = click.option("--json", default=False, is_flag=True, help="Dump the output as JSON to standard out")(fn)
    fn = click.option("--exit-non-zero-on-finding", default=False, is_flag=True,
                      help="Exit with a non-zero status code if at least one issue is identified")(fn)
    fn = click.option("-r", "--rules", multiple=True, type=click.Choice(ALL_RULES, case_sensitive=False))(fn)
    fn = click.option("-x", "--exclude-rules", multiple=True, type=click.Choice(ALL_RULES, case_sensitive=False))(fn)
    fn = click.argument("target")(fn)
    return fn


def version_option(fn):
    return click.option("-v", "--version", default=None, help="Specify a version to scan")(fn)


@click.group
def cli(**kwargs):
    """
    GuardDog cli tool to detect malware in package ecosystems

    Supports PyPI and npm

    Example: guarddog pypi scan semantic-version

    Use --help for the detail of all commands and subcommands
    """
    pass


def _get_rule_pram(rules, exclude_rules):
    rule_param = None
    if len(rules) > 0:
        rule_param = rules
    if len(exclude_rules) > 0:
        rule_param = ALL_RULES - set(exclude_rules)
        if len(rules) > 0:
            print("--rules and --exclude-rules have been used together. --rules will be ignored.")
    return rule_param


def _verify(path, rules, exclude_rules, json, exit_non_zero_on_finding, ecosystem):
    """Verify a requirements.txt file

    Args:
        path (str): path to requirements.txt file
    """
    rule_param = _get_rule_pram(rules, exclude_rules)
    scanner = get_scanner(ecosystem, True)
    if scanner is None:
        sys.stderr.write(f"Command verify is not supported for ecosystem {ecosystem}")
        exit(1)
    results = scanner.scan_local(path, rule_param)
    for result in results:
        identifier = result['dependency'] if result['version'] is None \
            else f"{result['dependency']} version {result['version']}"
        if not json:
            print_scan_results(result.get('result'), identifier)

    if json:
        import json as js
        print(js.dumps(results))

    if exit_non_zero_on_finding:
        exit_with_status_code(results)


def _scan(identifier, version, rules, exclude_rules, json, exit_non_zero_on_finding, ecosystem: ECOSYSTEM):
    """Scan a package

    Args:
        identifier (str): name or path to the package
        version (str): version of the package (ex. 1.0.0), defaults to most recent
        rules (str): specific rules to run, defaults to all
    """

    rule_param = _get_rule_pram(rules, exclude_rules)
    scanner = cast(Optional[PackageScanner], get_scanner(ecosystem, False))
    if scanner is None:
        sys.stderr.write(f"Command scan is not supported for ecosystem {ecosystem}")
        exit(1)
    results = {}
    if is_local_package(identifier, ecosystem):
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


@cli.group
def npm(**kwargs):
    """ Scan a npm package or verify a npm project
    @param kwargs:
    @return:
    """
    pass


@cli.group
def pypi(**kwargs):
    """ Scan a PyPI package or verify a PyPI project
    """
    pass


@npm.command("scan")
@common_options
@version_option
def scan_npm(target, version, rules, exclude_rules, json, exit_non_zero_on_finding):
    """ Scan a given npm package
    """
    return _scan(target, version, rules, exclude_rules, json, exit_non_zero_on_finding, ECOSYSTEM.NPM)


@npm.command("verify")
@common_options
def verify_npm(target, rules, exclude_rules, json, exit_non_zero_on_finding):
    """ Verify a given npm project
    """
    return _verify(target, rules, exclude_rules, json, exit_non_zero_on_finding, ECOSYSTEM.NPM)


@pypi.command("scan")
@common_options
@version_option
def scan_pypi(target, version, rules, exclude_rules, json, exit_non_zero_on_finding):
    """ Scan a given PyPI package
    """
    return _scan(target, version, rules, exclude_rules, json, exit_non_zero_on_finding, ECOSYSTEM.PYPI)


@pypi.command("verify")
@common_options
def verify_pypi(target, rules, exclude_rules, json, exit_non_zero_on_finding):
    """ Verify a given Pypi project
    """
    return _verify(target, rules, exclude_rules, json, exit_non_zero_on_finding, ECOSYSTEM.PYPI)


@cli.command(context_settings={"ignore_unknown_options": True}, deprecated=True)
@click.argument('target', nargs=-1)
def verify(target):
    exit(1)


@cli.command(context_settings={"ignore_unknown_options": True}, deprecated=True)
@click.argument('target', nargs=-1)
def scan(target):
    exit(1)


# Determines if the input passed to the 'scan' command is a local package name
def is_local_package(input: str, ecosystem: ECOSYSTEM):
    # FIXME: will break on scoped npm packages
    identifier_is_path = re.search(r"(.{0,2}\/)+.+", input)
    return identifier_is_path or input.endswith('.tar.gz')


# Pretty prints scan results for the console
def print_scan_results(results, identifier):
    num_issues = results.get('issues')

    if num_issues == 0:
        print("Found " + colored('0 potentially malicious indicators', 'green',
                                 attrs=['bold']) + " scanning " + colored(identifier, None, attrs=['bold']))
        print()
        return

    print("Found " + colored(str(num_issues) + ' potentially malicious indicators', 'red',
                             attrs=['bold']) + " in " + colored(identifier, None, attrs=['bold']))
    print()

    results = results.get('results', [])
    for finding in results:
        description = results[finding]
        if type(description) == str:  # package metadata
            print(colored(finding, None, attrs=['bold']) + ': ' + description)
            print()
        elif type(description) == list:  # semgrep rule result:
            source_code_findings = description
            print(colored(finding, None,
                          attrs=['bold']) + ': found ' + str(len(source_code_findings)) + ' source code matches')
            for finding in source_code_findings:
                print('  * ' + finding['message']
                      + ' at ' + finding['location'] + '\n    ' + format_code_line_for_output(finding['code']))
            print()


def format_code_line_for_output(code):
    return '    ' + colored(code.strip().replace('\n', '\n    ').replace('\t', '  '), None, 'on_red', attrs=['bold'])


# Given the results, exit with the appropriate status code
def exit_with_status_code(results):
    num_issues = results.get('issues', 0)
    if num_issues > 0:
        exit(EXIT_CODE_ISSUES_FOUND)
