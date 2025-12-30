"""
Risk-Based Scoring Engine for GuardDog

This module implements a risk correlation and scoring system that:
1. Correlates capabilities with threats to form risks
2. Scores packages based on attack chain completeness and sophistication
3. Uses MITRE ATT&CK tactics to understand attack progression
"""

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Dict
from collections import Counter
import logging

log = logging.getLogger("guarddog")


# ============================================================================
# Constants and Enums
# ============================================================================


class Level(str, Enum):
    """Categorical levels for severity, specificity, and sophistication"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RiskLabel(str, Enum):
    """Risk severity labels"""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# Mapping of severity/specificity/sophistication levels to numeric values
SEVERITY_VALUES = {Level.LOW: 1, Level.MEDIUM: 2, Level.HIGH: 3}

LEVEL_VALUES = {Level.LOW: 0.3, Level.MEDIUM: 0.7, Level.HIGH: 1.0}

# MITRE ATT&CK tactics grouped by attack phase
ATTACK_PHASES = {
    "early": ["reconnaissance", "resource-development", "initial-access", "execution"],
    "mid": [
        "persistence",
        "privilege-escalation",
        "defense-evasion",
        "credential-access",
        "discovery",
    ],
    "late": [
        "lateral-movement",
        "collection",
        "command-and-control",
        "exfiltration",
        "impact",
    ],
}

# Valid categories for the identifies field (system resources only)
VALID_CATEGORIES = {"network", "filesystem", "process", "runtime"}

# Valid types for the identifies field
VALID_TYPES = {"capability", "threat"}


# ============================================================================
# Data Models
# ============================================================================


@dataclass
class Finding:
    """
    A single rule match from Semgrep or YARA

    Attributes:
        rule_name: Name of the rule that matched
        file_path: Path to the file where the match occurred
        identifies: What this rule detects (e.g., "threat.network.outbound")
        severity: Impact level (low/medium/high)
        mitre_tactics: List of MITRE ATT&CK tactics
        specificity: Pattern specificity - how specific to malware vs legitimate code (low/medium/high)
        sophistication: Technique advancement level (low/medium/high)
        max_hits: Maximum number of risks to form from this rule per file (None = unlimited)
        location: Specific location in file (line number, offset)
        code_snippet: Matched code
        message: Description of what was found
    """

    rule_name: str
    file_path: str
    identifies: str
    severity: Level
    mitre_tactics: List[str]
    specificity: Level = Level.MEDIUM
    sophistication: Level = Level.MEDIUM
    max_hits: Optional[int] = None
    location: Optional[str] = None
    code_snippet: Optional[str] = None
    message: Optional[str] = None

    @property
    def type(self) -> str:
        """Returns 'capability' or 'threat'"""
        return self.identifies.split(".")[0]

    @property
    def category(self) -> str:
        """Returns category: network, filesystem, process, runtime"""
        parts = self.identifies.split(".")
        return parts[1] if len(parts) > 1 else None

    @property
    def detail(self) -> Optional[str]:
        """Returns detail: outbound, inbound, read, write, etc."""
        parts = self.identifies.split(".")
        return parts[2] if len(parts) > 2 else None


@dataclass
class Risk:
    """
    A formed risk from correlating capability + threat (or runtime threat alone)

    Attributes:
        category: Risk category (network, filesystem, process, runtime)
        detail: Optional detail (outbound, read, etc.)
        severity: Severity level from threat
        mitre_tactics: MITRE ATT&CK tactics from threat
        specificity: Pattern specificity - how specific to malware
        sophistication: Sophistication level
        threat_finding: The threat finding that formed this risk
        capability_finding: The capability finding (None for runtime threats)
    """

    category: str
    detail: Optional[str]
    severity: Level
    mitre_tactics: List[str]
    specificity: Level
    sophistication: Level
    threat_finding: Finding
    capability_finding: Optional[Finding]

    @property
    def name(self) -> str:
        """Returns risk name: 'risk.network' or 'risk.network.outbound'"""
        if self.detail:
            return f"risk.{self.category}.{self.detail}"
        return f"risk.{self.category}"


@dataclass
class RiskScore:
    """
    Complete risk scoring result for a package

    Attributes:
        score: Numeric score from 0-10
        label: Risk label (none/low/medium/high)
        risks: List of Risk objects found
        findings: List of all Finding objects
        score_breakdown: Dict showing how each factor contributed
    """

    score: float
    label: RiskLabel
    risks: List[Risk]
    findings: List[Finding]
    score_breakdown: Dict[str, float]


# ============================================================================
# Validation
# ============================================================================


def validate_identifies(identifies: str) -> bool:
    """
    Validates the 'identifies' field format

    Expected format: {type}.{category}[.{specificity}]
    - type: capability | threat
    - category: network | filesystem | process | runtime
    - specificity: optional additional detail

    Returns:
        True if valid, False otherwise
    """
    parts = identifies.split(".")

    if len(parts) < 2:
        return False

    type_part = parts[0]
    category_part = parts[1]

    if type_part not in VALID_TYPES:
        log.warning(
            f"Invalid type in identifies '{identifies}': must be 'capability' or 'threat'"
        )
        return False

    if category_part not in VALID_CATEGORIES:
        log.warning(
            f"Invalid category in identifies '{identifies}': must be one of {VALID_CATEGORIES}"
        )
        return False

    return True


def validate_mitre_tactics(tactics: List[str]) -> bool:
    """
    Validates that MITRE tactics are recognized

    Returns:
        True if all tactics are valid, False otherwise
    """
    all_valid_tactics = set()
    for phase_tactics in ATTACK_PHASES.values():
        all_valid_tactics.update(phase_tactics)

    invalid_tactics = [t for t in tactics if t not in all_valid_tactics]

    if invalid_tactics:
        log.warning(f"Unknown MITRE tactics: {invalid_tactics}")
        return False

    return True


# ============================================================================
# Risk Formation
# ============================================================================


def can_form_risk(threat: Finding, capability: Finding) -> bool:
    """
    Check if a threat and capability can form a risk

    Rules:
    1. Same category (network + network, filesystem + filesystem)
    2. Detail compatibility:
       - If either is general (None): match
       - If both specific: must be identical

    Args:
        threat: Threat finding
        capability: Capability finding

    Returns:
        True if they can form a risk, False otherwise
    """
    # Must be same category
    if threat.category != capability.category:
        return False

    # Check detail compatibility
    threat_detail = threat.detail
    cap_detail = capability.detail

    # If either is general (None), they match
    if threat_detail is None or cap_detail is None:
        return True

    # Both specific: must be identical
    return threat_detail == cap_detail


def form_risks_from_findings(findings: List[Finding]) -> List[Risk]:
    """
    Form risks from findings in the same file

    Args:
        findings: List of Finding objects from the same file

    Returns:
        List of Risk objects (limited by max_hits per rule)
    """
    from collections import defaultdict

    # Group findings by rule_name to apply max_hits per rule
    findings_by_rule = defaultdict(list)
    for finding in findings:
        findings_by_rule[finding.rule_name].append(finding)

    # Apply max_hits limit per rule
    limited_findings = []
    for rule_name, rule_findings in findings_by_rule.items():
        # Get max_hits from first finding of this rule (all have same value)
        max_hits = rule_findings[0].max_hits

        if max_hits is not None and len(rule_findings) > max_hits:
            # Limit to max_hits findings
            limited_findings.extend(rule_findings[:max_hits])
        else:
            # Take all findings
            limited_findings.extend(rule_findings)

    # Now form risks from the limited findings
    capabilities = [f for f in limited_findings if f.type == "capability"]
    threats = [f for f in limited_findings if f.type == "threat"]

    risks = []

    for threat in threats:
        # Runtime threats auto-form risks (no capability needed)
        if threat.category == "runtime":
            risks.append(
                Risk(
                    category=threat.category,
                    detail=threat.detail,
                    severity=threat.severity,
                    mitre_tactics=threat.mitre_tactics,
                    specificity=threat.specificity,
                    sophistication=threat.sophistication,
                    threat_finding=threat,
                    capability_finding=None,
                )
            )
            continue

        # Find matching capability for non-runtime threats
        for capability in capabilities:
            if can_form_risk(threat, capability):
                risks.append(
                    Risk(
                        category=threat.category,
                        detail=threat.detail or capability.detail,
                        severity=threat.severity,
                        mitre_tactics=threat.mitre_tactics,
                        specificity=threat.specificity,
                        sophistication=threat.sophistication,
                        threat_finding=threat,
                        capability_finding=capability,
                    )
                )
                break  # One threat can form at most one risk per file

    return risks


# ============================================================================
# Scoring
# ============================================================================


def get_primary_phase(risk: Risk) -> Optional[str]:
    """
    Get the primary attack phase from the first MITRE tactic

    Args:
        risk: Risk object

    Returns:
        Phase name ('early', 'mid', 'late') or None if no tactics
    """
    if not risk.mitre_tactics:
        return None

    primary_tactic = risk.mitre_tactics[0]

    for phase, tactics in ATTACK_PHASES.items():
        if primary_tactic in tactics:
            return phase

    log.warning(f"Unknown MITRE tactic '{primary_tactic}' for risk {risk.name}")
    return None


def get_dominant_level(levels: List[Level]) -> Level:
    """
    Get the dominant level from a list

    Rules:
    - If >50% are low: return low
    - If any high: return high
    - Otherwise: return medium

    Args:
        levels: List of Level values

    Returns:
        Dominant Level
    """
    if not levels:
        return Level.MEDIUM

    counts = Counter(levels)

    # If more than half are low, overall is low
    if counts[Level.LOW] > len(levels) / 2:
        return Level.LOW
    # If any high, overall is high
    elif counts.get(Level.HIGH, 0) > 0:
        return Level.HIGH
    else:
        return Level.MEDIUM


def has_credential_access_with_exfil(risks: List[Risk]) -> bool:
    """
    Check if package has credential access + network exfiltration

    This is a special case: credential theft with exfiltration should
    be treated as a full attack chain even without traditional early-stage execution.

    Args:
        risks: List of Risk objects

    Returns:
        True if credential-access + network exfiltration detected
    """
    has_credential_access = False
    has_network_exfil = False

    for risk in risks:
        if "credential-access" in risk.mitre_tactics:
            has_credential_access = True
        if risk.category == "network" and any(
            t in ["exfiltration", "command-and-control"] for t in risk.mitre_tactics
        ):
            has_network_exfil = True

    return has_credential_access and has_network_exfil


def calculate_risk_score(risks: List[Risk]) -> RiskScore:
    """
    Calculate final risk score using Factor Rating method

    Scoring factors (weights):
    - Severity (25%): Highest severity finding
    - Attack Chain (30%): Presence of complete attack stages
    - Specificity (25%): Pattern specificity (how specific to malware vs legitimate code)
    - Sophistication (20%): Technique sophistication level

    Args:
        risks: List of Risk objects for a package

    Returns:
        RiskScore object with score, label, and breakdown
    """
    if not risks:
        return RiskScore(
            score=0.0,
            label=RiskLabel.NONE,
            risks=[],
            findings=[],
            score_breakdown={
                "severity_component": 0.0,
                "chain_component": 0.0,
                "specificity_component": 0.0,
                "sophistication_component": 0.0,
            },
        )

    # Factor 1: Severity (25% weight)
    max_severity = max(SEVERITY_VALUES[r.severity] for r in risks)
    severity_component = (max_severity / 3.0) * 0.25

    # Factor 2: Attack Chain (30% weight)
    phase_risks = {"early": [], "mid": [], "late": []}
    for risk in risks:
        phase = get_primary_phase(risk)
        if phase in phase_risks:
            phase_risks[phase].append(risk)

    has_early = len(phase_risks["early"]) > 0
    has_mid_or_late = len(phase_risks["mid"]) > 0 or len(phase_risks["late"]) > 0
    has_full_chain = has_early and has_mid_or_late

    # Special case: credential access + network exfiltration = full chain
    if not has_full_chain and has_credential_access_with_exfil(risks):
        has_full_chain = True
        log.debug("Treating credential-access + exfiltration as full chain")

    chain_value = 1.0 if has_full_chain else 0.5
    chain_component = chain_value * 0.30

    # Factor 3: Specificity (25% weight)
    specificity_levels = [r.specificity for r in risks]
    dominant_specificity = get_dominant_level(specificity_levels)
    specificity_component = LEVEL_VALUES[dominant_specificity] * 0.25

    # Factor 4: Sophistication (20% weight)
    sophistication_levels = [r.sophistication for r in risks]
    dominant_sophistication = get_dominant_level(sophistication_levels)
    sophistication_component = LEVEL_VALUES[dominant_sophistication] * 0.20

    # Calculate final score
    raw_score = (
        severity_component
        + chain_component
        + specificity_component
        + sophistication_component
    )
    final_score = round(raw_score * 10, 1)

    # Map to label
    if final_score == 0:
        label = RiskLabel.NONE
    elif final_score <= 3:
        label = RiskLabel.LOW
    elif final_score <= 6:
        label = RiskLabel.MEDIUM
    else:
        label = RiskLabel.HIGH

    # Collect all findings
    all_findings = []
    for risk in risks:
        all_findings.append(risk.threat_finding)
        if risk.capability_finding:
            all_findings.append(risk.capability_finding)

    return RiskScore(
        score=final_score,
        label=label,
        risks=risks,
        findings=all_findings,
        score_breakdown={
            "severity_component": round(severity_component, 3),
            "chain_component": round(chain_component, 3),
            "specificity_component": round(specificity_component, 3),
            "sophistication_component": round(sophistication_component, 3),
            "has_full_chain": has_full_chain,
            "max_severity": max_severity,
            "dominant_specificity": dominant_specificity.value,
            "dominant_sophistication": dominant_sophistication.value,
        },
    )
