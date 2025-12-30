"""
Unit tests for the risk engine
"""

import pytest

from guarddog.analyzer.risk_engine import (
    Finding,
    Risk,
    Level,
    RiskLabel,
    can_form_risk,
    form_risks_from_findings,
    calculate_risk_score,
    validate_identifies,
    validate_mitre_tactics,
)


class TestValidation:
    """Test validation functions"""

    def test_validate_identifies_valid(self):
        assert validate_identifies("capability.network") is True
        assert validate_identifies("threat.network.outbound") is True
        assert validate_identifies("capability.filesystem.read") is True
        assert validate_identifies("threat.runtime.obfuscation") is True

    def test_validate_identifies_invalid(self):
        assert validate_identifies("invalid") is False
        assert validate_identifies("capability") is False
        assert validate_identifies("capability.invalid") is False
        assert validate_identifies("wrongtype.network") is False

    def test_validate_mitre_tactics_valid(self):
        assert validate_mitre_tactics(["execution"]) is True
        assert validate_mitre_tactics(["defense-evasion", "exfiltration"]) is True

    def test_validate_mitre_tactics_invalid(self):
        assert validate_mitre_tactics(["invalid-tactic"]) is False


class TestRiskFormation:
    """Test risk formation logic"""

    def test_can_form_risk_same_category_general(self):
        """General capability matches specific threat"""
        threat = Finding(
            rule_name="test",
            file_path="test.py",
            identifies="threat.network.outbound",
            severity=Level.HIGH,
            mitre_tactics=["exfiltration"],
        )
        capability = Finding(
            rule_name="test",
            file_path="test.py",
            identifies="capability.network",
            severity=Level.LOW,
            mitre_tactics=[],
        )
        assert can_form_risk(threat, capability) is True

    def test_can_form_risk_exact_match(self):
        """Exact specificity match"""
        threat = Finding(
            rule_name="test",
            file_path="test.py",
            identifies="threat.network.outbound",
            severity=Level.HIGH,
            mitre_tactics=["exfiltration"],
        )
        capability = Finding(
            rule_name="test",
            file_path="test.py",
            identifies="capability.network.outbound",
            severity=Level.LOW,
            mitre_tactics=[],
        )
        assert can_form_risk(threat, capability) is True

    def test_can_form_risk_specificity_conflict(self):
        """Conflicting specificity should not match"""
        threat = Finding(
            rule_name="test",
            file_path="test.py",
            identifies="threat.network.outbound",
            severity=Level.HIGH,
            mitre_tactics=["exfiltration"],
        )
        capability = Finding(
            rule_name="test",
            file_path="test.py",
            identifies="capability.network.inbound",
            severity=Level.LOW,
            mitre_tactics=[],
        )
        assert can_form_risk(threat, capability) is False

    def test_can_form_risk_different_category(self):
        """Different categories should not match"""
        threat = Finding(
            rule_name="test",
            file_path="test.py",
            identifies="threat.network",
            severity=Level.HIGH,
            mitre_tactics=["exfiltration"],
        )
        capability = Finding(
            rule_name="test",
            file_path="test.py",
            identifies="capability.filesystem",
            severity=Level.LOW,
            mitre_tactics=[],
        )
        assert can_form_risk(threat, capability) is False

    def test_runtime_threat_forms_risk(self):
        """Runtime threats should form risks without capability"""
        findings = [
            Finding(
                rule_name="obfuscation",
                file_path="test.py",
                identifies="threat.runtime.obfuscation",
                severity=Level.HIGH,
                mitre_tactics=["defense-evasion"],
            )
        ]
        risks = form_risks_from_findings(findings)
        assert len(risks) == 1
        assert risks[0].category == "runtime"
        assert risks[0].capability_finding is None

    def test_capability_threat_forms_risk(self):
        """Capability + threat should form risk"""
        findings = [
            Finding(
                rule_name="network-cap",
                file_path="test.py",
                identifies="capability.network",
                severity=Level.LOW,
                mitre_tactics=[],
            ),
            Finding(
                rule_name="network-threat",
                file_path="test.py",
                identifies="threat.network.outbound",
                severity=Level.HIGH,
                mitre_tactics=["exfiltration"],
            ),
        ]
        risks = form_risks_from_findings(findings)
        assert len(risks) == 1
        assert risks[0].category == "network"
        assert risks[0].capability_finding is not None

    def test_no_risk_without_capability(self):
        """Threat without matching capability should not form risk"""
        findings = [
            Finding(
                rule_name="network-threat",
                file_path="test.py",
                identifies="threat.network",
                severity=Level.HIGH,
                mitre_tactics=["exfiltration"],
            )
        ]
        risks = form_risks_from_findings(findings)
        assert len(risks) == 0


class TestScoring:
    """Test scoring algorithm"""

    def test_no_risks_returns_zero(self):
        score = calculate_risk_score([])
        assert score.score == 0.0
        assert score.label == RiskLabel.NONE

    def test_single_runtime_threat(self):
        """Single runtime threat should score medium"""
        risks = [
            Risk(
                category="runtime",
                detail="obfuscation",
                severity=Level.HIGH,
                mitre_tactics=["defense-evasion"],
                specificity=Level.HIGH,
                sophistication=Level.HIGH,
                threat_finding=Finding(
                    rule_name="obf",
                    file_path="test.py",
                    identifies="threat.runtime.obfuscation",
                    severity=Level.HIGH,
                    mitre_tactics=["defense-evasion"],
                ),
                capability_finding=None,
            )
        ]
        score = calculate_risk_score(risks)
        # No full chain (only mid-stage), high severity/specificity/sophistication
        # Expected: (1.0*0.25) + (0.5*0.30) + (1.0*0.25) + (1.0*0.20) = 0.85 * 10 = 8.5
        assert score.score == 8.5
        assert score.label == RiskLabel.HIGH

    def test_full_attack_chain(self):
        """Full attack chain should score high"""
        risks = [
            Risk(
                category="process",
                detail="spawn",
                severity=Level.HIGH,
                mitre_tactics=["execution"],
                specificity=Level.HIGH,
                sophistication=Level.MEDIUM,
                threat_finding=Finding(
                    rule_name="exec",
                    file_path="test.py",
                    identifies="threat.process.spawn",
                    severity=Level.HIGH,
                    mitre_tactics=["execution"],
                ),
                capability_finding=Finding(
                    rule_name="cap",
                    file_path="test.py",
                    identifies="capability.process.spawn",
                    severity=Level.LOW,
                    mitre_tactics=[],
                ),
            ),
            Risk(
                category="network",
                detail="outbound",
                severity=Level.HIGH,
                mitre_tactics=["exfiltration"],
                specificity=Level.HIGH,
                sophistication=Level.MEDIUM,
                threat_finding=Finding(
                    rule_name="net",
                    file_path="test.py",
                    identifies="threat.network.outbound",
                    severity=Level.HIGH,
                    mitre_tactics=["exfiltration"],
                ),
                capability_finding=Finding(
                    rule_name="cap2",
                    file_path="test.py",
                    identifies="capability.network",
                    severity=Level.LOW,
                    mitre_tactics=[],
                ),
            ),
        ]
        score = calculate_risk_score(risks)
        # Full chain (early + late), high severity/specificity, medium sophistication
        # Expected: (1.0*0.25) + (1.0*0.30) + (1.0*0.25) + (0.7*0.20) = 0.94 * 10 = 9.4
        assert score.score == 9.4
        assert score.label == RiskLabel.HIGH

    def test_credential_access_with_exfil_is_full_chain(self):
        """Credential access + network exfiltration should be treated as full chain"""
        risks = [
            Risk(
                category="filesystem",
                detail="read",
                severity=Level.HIGH,
                mitre_tactics=["credential-access"],
                specificity=Level.HIGH,
                sophistication=Level.LOW,
                threat_finding=Finding(
                    rule_name="creds",
                    file_path="test.py",
                    identifies="threat.filesystem.read",
                    severity=Level.HIGH,
                    mitre_tactics=["credential-access"],
                ),
                capability_finding=Finding(
                    rule_name="fs",
                    file_path="test.py",
                    identifies="capability.filesystem.read",
                    severity=Level.LOW,
                    mitre_tactics=[],
                ),
            ),
            Risk(
                category="network",
                detail="outbound",
                severity=Level.HIGH,
                mitre_tactics=["exfiltration"],
                specificity=Level.HIGH,
                sophistication=Level.MEDIUM,
                threat_finding=Finding(
                    rule_name="net",
                    file_path="test.py",
                    identifies="threat.network.outbound",
                    severity=Level.HIGH,
                    mitre_tactics=["exfiltration"],
                ),
                capability_finding=Finding(
                    rule_name="cap",
                    file_path="test.py",
                    identifies="capability.network",
                    severity=Level.LOW,
                    mitre_tactics=[],
                ),
            ),
        ]
        score = calculate_risk_score(risks)
        # Should be treated as full chain despite no execution
        assert score.score_breakdown["has_full_chain"] is True
        # Dominant sophistication is medium (one high, one medium) so: (1.0*0.25) + (1.0*0.30) + (1.0*0.25) + (0.7*0.20) = 0.94 * 10
        assert score.score == 9.4
        assert score.label == RiskLabel.HIGH
