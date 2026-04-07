"""
AGENT ANONMUSK — CVSS v3.1 Calculator
=====================================
Automated CVSS score calculation based on vulnerability context.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from core.context import VulnType


class AttackVector(Enum):
    NETWORK = ("N", 0.85)
    ADJACENT = ("A", 0.62)
    LOCAL = ("L", 0.55)
    PHYSICAL = ("P", 0.20)


class AttackComplexity(Enum):
    LOW = ("L", 0.77)
    HIGH = ("H", 0.44)


class PrivilegesRequired(Enum):
    NONE = ("N", 0.85, 0.85)    # (code, unchanged_scope, changed_scope)
    LOW = ("L", 0.62, 0.68)
    HIGH = ("H", 0.27, 0.50)


class UserInteraction(Enum):
    NONE = ("N", 0.85)
    REQUIRED = ("R", 0.62)


class Scope(Enum):
    UNCHANGED = "U"
    CHANGED = "C"


class Impact(Enum):
    NONE = ("N", 0.0)
    LOW = ("L", 0.22)
    HIGH = ("H", 0.56)


class CVSSCalculator:
    """
    CVSS v3.1 Base Score Calculator.

    Usage:
        calc = CVSSCalculator()
        score, vector = calc.calculate(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.NONE,
        )
        # → 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    """

    @staticmethod
    def calculate(
        attack_vector: AttackVector = AttackVector.NETWORK,
        attack_complexity: AttackComplexity = AttackComplexity.LOW,
        privileges_required: PrivilegesRequired = PrivilegesRequired.NONE,
        user_interaction: UserInteraction = UserInteraction.NONE,
        scope: Scope = Scope.UNCHANGED,
        confidentiality: Impact = Impact.NONE,
        integrity: Impact = Impact.NONE,
        availability: Impact = Impact.NONE,
    ) -> tuple[float, str]:
        """
        Calculate CVSS v3.1 base score.

        Returns:
            (score, vector_string) tuple
        """
        # Exploitability sub-score
        av_val = attack_vector.value[1]
        ac_val = attack_complexity.value[1]
        ui_val = user_interaction.value[1]

        # PR depends on scope
        if scope == Scope.CHANGED:
            pr_val = privileges_required.value[2]
        else:
            pr_val = privileges_required.value[1]

        exploitability = 8.22 * av_val * ac_val * pr_val * ui_val

        # Impact sub-score
        c_val = confidentiality.value[1]
        i_val = integrity.value[1]
        a_val = availability.value[1]

        iss = 1 - ((1 - c_val) * (1 - i_val) * (1 - a_val))

        if scope == Scope.UNCHANGED:
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

        # Base score
        if impact <= 0:
            base_score = 0.0
        elif scope == Scope.UNCHANGED:
            base_score = min(impact + exploitability, 10.0)
            base_score = _roundup(base_score)
        else:
            base_score = min(1.08 * (impact + exploitability), 10.0)
            base_score = _roundup(base_score)

        # Vector string
        vector = (
            f"CVSS:3.1/AV:{attack_vector.value[0]}/"
            f"AC:{attack_complexity.value[0]}/"
            f"PR:{privileges_required.value[0]}/"
            f"UI:{user_interaction.value[0]}/"
            f"S:{scope.value}/"
            f"C:{confidentiality.value[0]}/"
            f"I:{integrity.value[0]}/"
            f"A:{availability.value[0]}"
        )

        return base_score, vector

    @staticmethod
    def auto_score(vuln_type: VulnType) -> tuple[float, str]:
        """
        Auto-calculate CVSS based on vulnerability type.
        Uses reasonable defaults for each vulnerability class.
        """
        calc = CVSSCalculator()

        VULN_PROFILES = {
            VulnType.SQLI: {
                "attack_vector": AttackVector.NETWORK,
                "attack_complexity": AttackComplexity.LOW,
                "privileges_required": PrivilegesRequired.NONE,
                "user_interaction": UserInteraction.NONE,
                "scope": Scope.UNCHANGED,
                "confidentiality": Impact.HIGH,
                "integrity": Impact.HIGH,
                "availability": Impact.NONE,
            },
            VulnType.CMDI: {
                "attack_vector": AttackVector.NETWORK,
                "attack_complexity": AttackComplexity.LOW,
                "privileges_required": PrivilegesRequired.NONE,
                "user_interaction": UserInteraction.NONE,
                "scope": Scope.CHANGED,
                "confidentiality": Impact.HIGH,
                "integrity": Impact.HIGH,
                "availability": Impact.HIGH,
            },
            VulnType.XSS: {
                "attack_vector": AttackVector.NETWORK,
                "attack_complexity": AttackComplexity.LOW,
                "privileges_required": PrivilegesRequired.NONE,
                "user_interaction": UserInteraction.REQUIRED,
                "scope": Scope.CHANGED,
                "confidentiality": Impact.LOW,
                "integrity": Impact.LOW,
                "availability": Impact.NONE,
            },
            VulnType.BOLA: {
                "attack_vector": AttackVector.NETWORK,
                "attack_complexity": AttackComplexity.LOW,
                "privileges_required": PrivilegesRequired.LOW,
                "user_interaction": UserInteraction.NONE,
                "scope": Scope.UNCHANGED,
                "confidentiality": Impact.HIGH,
                "integrity": Impact.LOW,
                "availability": Impact.NONE,
            },
            VulnType.AUTH_BYPASS: {
                "attack_vector": AttackVector.NETWORK,
                "attack_complexity": AttackComplexity.LOW,
                "privileges_required": PrivilegesRequired.NONE,
                "user_interaction": UserInteraction.NONE,
                "scope": Scope.UNCHANGED,
                "confidentiality": Impact.HIGH,
                "integrity": Impact.HIGH,
                "availability": Impact.NONE,
            },
            VulnType.SESSION_FIXATION: {
                "attack_vector": AttackVector.NETWORK,
                "attack_complexity": AttackComplexity.HIGH,
                "privileges_required": PrivilegesRequired.NONE,
                "user_interaction": UserInteraction.REQUIRED,
                "scope": Scope.UNCHANGED,
                "confidentiality": Impact.HIGH,
                "integrity": Impact.HIGH,
                "availability": Impact.NONE,
            },
            VulnType.RATE_LIMIT: {
                "attack_vector": AttackVector.NETWORK,
                "attack_complexity": AttackComplexity.LOW,
                "privileges_required": PrivilegesRequired.NONE,
                "user_interaction": UserInteraction.NONE,
                "scope": Scope.UNCHANGED,
                "confidentiality": Impact.NONE,
                "integrity": Impact.NONE,
                "availability": Impact.LOW,
            },
            VulnType.USERNAME_ENUM: {
                "attack_vector": AttackVector.NETWORK,
                "attack_complexity": AttackComplexity.LOW,
                "privileges_required": PrivilegesRequired.NONE,
                "user_interaction": UserInteraction.NONE,
                "scope": Scope.UNCHANGED,
                "confidentiality": Impact.LOW,
                "integrity": Impact.NONE,
                "availability": Impact.NONE,
            },
        }

        profile = VULN_PROFILES.get(vuln_type, {
            "attack_vector": AttackVector.NETWORK,
            "attack_complexity": AttackComplexity.LOW,
            "privileges_required": PrivilegesRequired.NONE,
            "user_interaction": UserInteraction.NONE,
            "scope": Scope.UNCHANGED,
            "confidentiality": Impact.LOW,
            "integrity": Impact.NONE,
            "availability": Impact.NONE,
        })

        return calc.calculate(**profile)


def _roundup(value: float) -> float:
    """CVSS roundup function (round up to 1 decimal)."""
    import math
    return math.ceil(value * 10) / 10


def severity_from_score(score: float) -> str:
    """Get severity rating from CVSS score."""
    if score == 0:
        return "info"
    elif score < 4.0:
        return "low"
    elif score < 7.0:
        return "medium"
    elif score < 9.0:
        return "high"
    else:
        return "critical"
