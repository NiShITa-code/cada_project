"""Control-evaluation harness: adversary tiers, defender tiers, matrix runner.

Implements the protocol defined in ``methodology/positioning_v3_control_eval.md``.
Each adversary and defender is a pluggable interface so the (A x D x O) matrix
is one loop in ``matrix.py``.
"""
from cada.control_eval.adversaries import (
    Adversary,
    A0_Honest,
    A1_StaticObf,
    A2_MonitorAware,
    A3_SandboxAware,
    A4_Combined,
    ADVERSARIES,
)
from cada.control_eval.defenders import (
    Defender,
    D0_NoDefender,
    D1_AntiFingerprint,
    D2_CapScope,
    D3_NoiseInjection,
    DEFENDERS,
)

__all__ = [
    "Adversary",
    "A0_Honest", "A1_StaticObf", "A2_MonitorAware", "A3_SandboxAware", "A4_Combined",
    "ADVERSARIES",
    "Defender",
    "D0_NoDefender", "D1_AntiFingerprint", "D2_CapScope", "D3_NoiseInjection",
    "DEFENDERS",
]
