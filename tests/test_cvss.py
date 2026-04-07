"""Tests for reporting.cvss module."""

import pytest
from reporting.cvss import (
    CVSSCalculator, AttackVector, AttackComplexity,
    PrivilegesRequired, UserInteraction, Scope,
    Impact, severity_from_score,
)
from core.context import VulnType


class TestCVSSCalculator:
    """Test CVSS v3.1 score calculation."""

    def test_critical_rce(self):
        """Command injection: AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H → 10.0"""
        score, vector = CVSSCalculator.calculate(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.CHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
        )
        assert score == 10.0
        assert "AV:N" in vector
        assert "S:C" in vector

    def test_reflected_xss(self):
        """Reflected XSS: AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N → 6.1"""
        score, vector = CVSSCalculator.calculate(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.REQUIRED,
            scope=Scope.CHANGED,
            confidentiality=Impact.LOW,
            integrity=Impact.LOW,
            availability=Impact.NONE,
        )
        assert score == 6.1

    def test_no_impact(self):
        """Zero impact → score should be 0.0"""
        score, _ = CVSSCalculator.calculate(
            confidentiality=Impact.NONE,
            integrity=Impact.NONE,
            availability=Impact.NONE,
        )
        assert score == 0.0

    def test_auto_score_sqli(self):
        score, vector = CVSSCalculator.auto_score(VulnType.SQLI)
        assert score >= 8.0  # SQLi should be high/critical
        assert "CVSS:3.1" in vector

    def test_auto_score_cmdi(self):
        score, vector = CVSSCalculator.auto_score(VulnType.CMDI)
        assert score == 10.0  # Command injection = critical

    def test_auto_score_xss(self):
        score, _ = CVSSCalculator.auto_score(VulnType.XSS)
        assert 5.0 <= score <= 7.0  # Medium range


class TestSeverityFromScore:
    def test_critical(self):
        assert severity_from_score(9.5) == "critical"

    def test_high(self):
        assert severity_from_score(7.5) == "high"

    def test_medium(self):
        assert severity_from_score(5.0) == "medium"

    def test_low(self):
        assert severity_from_score(2.0) == "low"

    def test_info(self):
        assert severity_from_score(0.0) == "info"
