"""
sdn/risk_engine.py - Pure risk-based decision logic for security alerts.

This module has no Flask, Faucet, or filesystem dependencies. It receives
normalised threat measurements, calculates a score, and selects the policy
action for the API layer to apply.
"""

from numbers import Real


ACTION_ALLOW = "allow"
ACTION_RATE_LIMIT = "rate_limit"
ACTION_QUARANTINE = "quarantine"
ACTION_BLOCK = "block"


def calculate_risk(
    confidence: float,
    severity: float,
    device_criticality: float,
) -> float:
    """
    Calculate a bounded risk score from three normalised threat factors.

    Args:
        confidence: NIDS/HIDS confidence, in the range 0.0 to 1.0.
        severity: Estimated threat severity, in the range 0.0 to 1.0.
        device_criticality: Importance of the affected device, in the range
            0.0 to 1.0.

    Returns:
        A risk score in the range 0.0 to 1.0.

    Raises:
        ValueError: If any factor is not numeric or is outside 0.0 to 1.0.
    """
    confidence = _validated_factor("confidence", confidence)
    severity = _validated_factor("severity", severity)
    device_criticality = _validated_factor(
        "device_criticality", device_criticality
    )

    score = (
        (confidence * 0.5)
        + (severity * 0.3)
        + (device_criticality * 0.2)
    )
    return max(0.0, min(1.0, score))


def select_action(risk_score: float) -> str:
    """
    Select the SDN response for a normalised risk score.

    Args:
        risk_score: Risk score in the range 0.0 to 1.0.

    Returns:
        One of ``allow``, ``rate_limit``, ``quarantine``, or ``block``.

    Raises:
        ValueError: If the score is not numeric or is outside 0.0 to 1.0.
    """
    risk_score = _validated_factor("risk_score", risk_score)

    if risk_score >= 0.9:
        return ACTION_BLOCK
    if risk_score > 0.7:
        return ACTION_QUARANTINE
    if risk_score >= 0.3:
        return ACTION_RATE_LIMIT
    return ACTION_ALLOW


def _validated_factor(name: str, value: float) -> float:
    """Convert and validate one normalised risk factor."""
    if isinstance(value, bool) or not isinstance(value, Real):
        raise ValueError(f"{name} must be a number between 0.0 and 1.0")

    value = float(value)
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be between 0.0 and 1.0")
    return value
