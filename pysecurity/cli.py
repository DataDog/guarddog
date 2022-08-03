""" PyPI Package Malware Scanner

CLI command that scans a PyPI package version for user-specified malware flags. 
Includes rules based on package registry metadata and source code analysis.
"""

import json
import os
import re
from pprint import pprint

import click

from pysecurity.scanners.package_scanner import PackageScanner
from pysecurity.scanners.project_scanner import RequirementsScanner


@click.group
def cli():
    """ Pysecurity cli tool to detect PyPI malware """
    pass
    

@cli.command("verify")
@click.argument('path')
@click.option('-o', '--output-file', default=None, type=click.Path(exists=False))
def verify(path, output_file):
    """ Verify a requirements.txt file

    Args:
        path (str): path to requirements.txt file
        output_file (str): path to output file
    """
    scanner = RequirementsScanner()
    results = scanner.scan_local(path)
    
    if output_file:
        basedir = os.path.dirname(output_file)
        is_basedir_exist = os.path.exists(basedir)
        
        if not is_basedir_exist:
            os.makedirs(basedir)
            
        with open(output_file, "w+") as f:
            json.dump(results, f, ensure_ascii=False, indent=4)
    else:      
        pprint(results)
    

@cli.command("scan")
@click.argument('identifier')
@click.option('-v', '--version', default=None)
@click.option('-r', '--rules', multiple=True)
def scan(identifier, version, rules):
    rule_param = None
    if len(rules) != 0:
        rule_param = rules
        
    scanner = PackageScanner()
    
    identifier_is_path = re.search(r'(.{0,2}\/)+.+', identifier)
    
    results = {}
    if identifier_is_path:
        results = scanner.scan_local(identifier, rule_param)
    else:
        results = scanner.scan_remote(identifier, version, rule_param)
    
    pprint(results)
