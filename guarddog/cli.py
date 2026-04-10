"""Package Malware Scanner

CLI command that scans a package version for user-specified malware flags.
Includes rules based on package registry metadata and source code analysis.
"""

from functools import reduce
import logging
import os
import sys
import tempfile
from typing import Optional

import click
from prettytable import PrettyTable

from guarddog.analyzer.metadata import get_metadata_detectors
from guarddog.analyzer.sourcecode import get_sourcecode_rules
from guarddog.ecosystems import ECOSYSTEM
from guarddog.reporters.reporter_factory import ReporterFactory, ReporterType

from guarddog.scanners import get_package_scanner, get_project_scanner
from guarddog.utils.archives import safe_extract

EXIT_CODE_ISSUES_FOUND = 1

AVAILABLE_LOG_LEVELS = {logging.DEBUG, logging.INFO, logging.WARN, logging.ERROR}
AVAILABLE_LOG_LEVELS_NAMES = list(
    map(lambda level: logging.getLevelName(level), AVAILABLE_LOG_LEVELS)
)

log = logging.getLogger("guarddog")


def common_options(fn):
    fn = click.option(
        "--exit-non-zero-on-finding",
        default=False,
        is_flag=True,
        help="Exit with a non-zero status code if at least one issue is identified",
    )(fn)
    fn = click.argument("target")(fn)
    return fn


def legacy_rules_options(fn):
    ALL_RULES = reduce(
        lambda a, b: a | b,
        map(
            lambda e: set(r.id for r in get_sourcecode_rules(e))
            | set(get_metadata_detectors(e).keys()),
            [e for e in ECOSYSTEM],
        ),
    )

    fn = click.option(
        "-r",
        "--rules",
        multiple=True,
        type=click.Choice(ALL_RULES, case_sensitive=False),
    )(fn)
    fn = click.option(
        "-x",
        "--exclude-rules",
        multiple=True,
        type=click.Choice(ALL_RULES, case_sensitive=False),
    )(fn)
    return fn


def verify_options(fn):
    fn = click.option(
        "--output-format",
        default=None,
        type=click.Choice(["json", "sarif"], case_sensitive=False),
    )(fn)
    return fn


def scan_options(fn):
    fn = click.option(
        "--output-format",
        default=None,
        type=click.Choice(["json"], case_sensitive=False),
    )(fn)
    fn = click.option(
        "-v", "--version", default=None, help="Specify a version to scan"
    )(fn)
    fn = click.option(
        "--sandbox/--no-sandbox",
        default=True,
        help="Enable/disable kernel-level sandbox (default: enabled)",
    )(fn)
    return fn


def logging_options(fn):
    fn = click.option(
        "--log-level",
        default="INFO",
        type=click.Choice(AVAILABLE_LOG_LEVELS_NAMES, case_sensitive=False),
    )(fn)
    return fn


@click.group
@logging_options
@click.version_option(message="%(version)s")
def cli(log_level):
    """
    GuardDog cli tool to detect malware in package ecosystems

    Supports PyPI, npm and Go modules.

    Example: guarddog pypi scan semantic-version

    Use --help for the detail of all commands and subcommands
    """
    logger = logging.getLogger("guarddog")
    logger.setLevel(logging.getLevelName(log_level))
    stderrHandler = logging.StreamHandler(stream=sys.stderr)
    stderrHandler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logger.addHandler(stderrHandler)


def _get_all_rules(ecosystem: ECOSYSTEM) -> set[str]:
    return set(r.id for r in get_sourcecode_rules(ecosystem)) | set(
        get_metadata_detectors(ecosystem).keys()
    )


def _get_rule_param(
    rules: tuple[str, ...], exclude_rules: tuple[str, ...], ecosystem: ECOSYSTEM
) -> Optional[set[str]]:
    """
    This function should return None if no rules are provided
    Else a set of rules to be used for scanning
    """
    rule_param = None
    if len(rules) > 0:
        rule_param = set(rules)

    if len(exclude_rules) > 0:
        all_rules = _get_all_rules(ecosystem)
        rule_param = all_rules - set(exclude_rules)

        if len(rules) > 0:
            log.error("--rules and --exclude-rules cannot be used together")
            sys.exit(1)

    return rule_param


def _verify(
    path, rules, exclude_rules, output_format, exit_non_zero_on_finding, ecosystem
):
    """Verify a requirements.txt file

    Args:
        path (str): path to requirements.txt file
    """
    return_value = None
    rule_param = _get_rule_param(rules, exclude_rules, ecosystem)
    scanner = get_project_scanner(ecosystem)
    if scanner is None:
        log.error(f"Command verify is not supported for ecosystem {ecosystem}")
        exit(1)

    dependencies, results = scanner.scan_local(path=path, rules=rule_param)

    rule_docs = list(rule_param or _get_all_rules(ecosystem=ecosystem))

    reporter = ReporterFactory.create_reporter(ReporterType.from_str(output_format))
    stdout, stderr = reporter.render_verify(
        dependency_files=dependencies,
        rule_names=rule_docs,
        scan_results=results,
        ecosystem=ecosystem,
    )

    sys.stdout.write(stdout)
    sys.stderr.write(stderr)

    if exit_non_zero_on_finding:
        exit_with_status_code([result["result"] for result in results])

    return return_value  # this is mostly for testing


def _scan(
    identifier,
    version,
    rules,
    exclude_rules,
    output_format,
    exit_non_zero_on_finding,
    ecosystem: ECOSYSTEM,
    sandbox: bool = True,
):
    """Scan a package

    Args:
        identifier (str): name or path to the package
        version (str): version of the package (ex. 1.0.0), defaults to most recent
        rules (list[str]): specific rules to run, defaults to all
        sandbox (bool): enable kernel-level sandbox (default True)
    """

    if sandbox:
        from guarddog.sandbox import is_available

        if not is_available():
            log.error(
                "Sandbox not supported on this platform. "
                "Use --no-sandbox to skip (not recommended)."
            )
            sys.exit(1)
    else:
        log.warning("Scanning without kernel-level sandbox protection.")

    rule_param = _get_rule_param(rules, exclude_rules, ecosystem)
    scanner = get_package_scanner(ecosystem)
    if scanner is None:
        log.error(f"Command scan is not supported for ecosystem {ecosystem}")
        sys.exit(1)

    result = {"package": identifier}
    try:
        if os.path.isdir(identifier):
            log.debug(f"Considering that '{identifier}' is a local directory")
            if sandbox:
                from guarddog.sandbox import apply_sandbox

                apply_sandbox(
                    scan_paths=[identifier],
                    writable_paths=[],
                )
            result |= scanner.scan_local(identifier, rule_param)

        elif os.path.isfile(identifier):
            log.debug(f"Considering that '{identifier}' is a local archive file")
            with tempfile.TemporaryDirectory() as tempdir:
                if sandbox:
                    from guarddog.sandbox import apply_sandbox

                    apply_sandbox(
                        scan_paths=[identifier],
                        writable_paths=[tempdir],
                    )
                safe_extract(identifier, tempdir)
                result |= scanner.scan_local(tempdir, rule_param)

        else:
            log.debug(f"Considering that '{identifier}' is a remote target")
            if sandbox:
                result |= _scan_remote_sandboxed(
                    scanner, identifier, version, rule_param
                )
            else:
                result |= scanner.scan_remote(identifier, version, rule_param)

    except Exception as e:
        log.error(f"Error occurred while scanning target {identifier}: '{e}'\n")
        sys.exit(1)

    reporter = ReporterFactory.create_reporter(ReporterType.from_str(output_format))
    stdout, stderr = reporter.render_scan(result)
    sys.stdout.write(stdout)
    sys.stderr.write(stderr)

    if exit_non_zero_on_finding:
        exit_with_status_code([result])


def _scan_remote_sandboxed(scanner, name, version, rules):
    """Two-phase remote scan: download + metadata (unsandboxed), then sandbox + sourcecode."""
    from guarddog.sandbox import apply_sandbox

    with tempfile.TemporaryDirectory() as tmpdir:
        # Phase 1: download package (needs network)
        package_info, file_path = scanner.download_package(name, tmpdir, version)

        # Phase 2: metadata analysis (needs network for whois, git clone, etc.)
        metadata_results = scanner.analyzer.analyze_metadata(
            file_path, package_info, rules, name, version
        )

        # Phase 3: apply sandbox (blocks network, restricts filesystem)
        apply_sandbox(
            scan_paths=[],
            writable_paths=[tmpdir],
        )

        # Phase 4: source code analysis (sandboxed)
        sourcecode_results = scanner.analyzer.analyze_sourcecode(file_path, rules)

        # Merge results (same logic as Analyzer.analyze)
        issues = metadata_results["issues"] + sourcecode_results["issues"]
        results = metadata_results["results"] | sourcecode_results["results"]
        errors = metadata_results["errors"] | sourcecode_results["errors"]

        risk_score = scanner.analyzer.calculate_package_risk_score(
            sourcecode_results, metadata_results
        )

        risk_objects = risk_score.pop("_risks", [])
        formatted_risks = [
            {
                "name": risk.name,
                "category": risk.category,
                "severity": risk.severity.value,
                "mitre_tactics": risk.mitre_tactics,
                "threat_identifies": risk.threat_finding.identifies,
                "threat_rule": risk.threat_finding.rule_name,
                "threat_description": risk.threat_finding.message or "",
                "threat_location": risk.threat_finding.location or "",
                "threat_code": risk.threat_finding.code_snippet or "",
                "capability_identifies": (
                    risk.capability_finding.identifies
                    if risk.capability_finding
                    else None
                ),
                "capability_rule": (
                    risk.capability_finding.rule_name
                    if risk.capability_finding
                    else None
                ),
                "file_path": risk.threat_finding.file_path,
            }
            for risk in risk_objects
        ]

        return {
            "issues": issues,
            "errors": errors,
            "results": results,
            "path": file_path,
            "risk_score": risk_score,
            "risks": formatted_risks,
        }


def _list_rules(ecosystem: ECOSYSTEM):
    table = PrettyTable()
    table.align = "l"
    table.field_names = ["Rule type", "Rule name", "Description"]

    for sc_rule in get_sourcecode_rules(ecosystem):
        table.add_row(["Source code", sc_rule.id, sc_rule.description])

    metadata_rules = get_metadata_detectors(ecosystem)
    for ruleName in metadata_rules:
        m_rule = metadata_rules[ruleName]
        table.add_row(["Package metadata", m_rule.get_name(), m_rule.get_description()])

    print(table)


# This class is used to create dynamic groups in the cli, each group is an ecosystem with the same options
class CliEcosystem(click.Group):
    """
    Class that dynamically represents an ecosystem in click
    It dynamically selects the ruleset to the instantiated ecosystem
    """

    def __init__(self, ecosystem: ECOSYSTEM):
        super().__init__()
        self.name = ecosystem.name.lower()
        self.ecosystem = ecosystem

        def rule_options(fn):
            rules = _get_all_rules(self.ecosystem)
            fn = click.option(
                "-r",
                "--rules",
                multiple=True,
                type=click.Choice(rules, case_sensitive=False),
            )(fn)
            fn = click.option(
                "-x",
                "--exclude-rules",
                multiple=True,
                type=click.Choice(rules, case_sensitive=False),
            )(fn)
            return fn

        @click.command("scan", help=f"Scan a given {self.ecosystem.name} package")
        @common_options
        @scan_options
        @rule_options
        def scan_ecosystem(
            target,
            version,
            rules,
            exclude_rules,
            output_format,
            exit_non_zero_on_finding,
            sandbox,
        ):
            return _scan(
                target,
                version,
                rules,
                exclude_rules,
                output_format,
                exit_non_zero_on_finding,
                self.ecosystem,
                sandbox=sandbox,
            )

        @click.command("verify", help=f"Verify a given {self.ecosystem.name} package")
        @common_options
        @verify_options
        @rule_options
        def verify_ecosystem(
            target, rules, exclude_rules, output_format, exit_non_zero_on_finding
        ):
            return _verify(
                target,
                rules,
                exclude_rules,
                output_format,
                exit_non_zero_on_finding,
                self.ecosystem,
            )

        @click.command(
            "list-rules", help=f"List available rules for {self.ecosystem.name}"
        )
        def list_rules_ecosystem():
            return _list_rules(self.ecosystem)

        self.add_command(scan_ecosystem, "scan")
        self.add_command(verify_ecosystem, "verify")
        self.add_command(list_rules_ecosystem, "list-rules")


# Adding all ecosystems as subcommands
for e in ECOSYSTEM:
    cli.add_command(CliEcosystem(e), e.name.lower())


@cli.command("verify", deprecated=True)
@common_options
@verify_options
@legacy_rules_options
def verify(target, rules, exclude_rules, output_format, exit_non_zero_on_finding):
    return verify(
        target,
        rules,
        exclude_rules,
        output_format,
        exit_non_zero_on_finding,
        ECOSYSTEM.PYPI,
    )


@cli.command("scan", deprecated=True)
@common_options
@scan_options
@legacy_rules_options
def scan(
    target, version, rules, exclude_rules, output_format, exit_non_zero_on_finding,
    sandbox,
):
    return _scan(
        target,
        version,
        rules,
        exclude_rules,
        output_format,
        exit_non_zero_on_finding,
        ECOSYSTEM.PYPI,
        sandbox=sandbox,
    )


# Given the results, exit with the appropriate status code
def exit_with_status_code(results):
    for result in results:
        num_issues = result.get("issues", 0)
        if num_issues > 0:
            exit(EXIT_CODE_ISSUES_FOUND)
