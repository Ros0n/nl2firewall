"""Safety Gate — hard blocker for unsafe CanonicalRules."""

from __future__ import annotations
from app.models.ir import CanonicalRule, Action, Protocol, SafetyResult


def run_safety_gate(rule: CanonicalRule | None) -> SafetyResult:
    if rule is None:
        return SafetyResult(safe=False, errors=["No rule provided"], message="No rule")

    errors: list[str] = []

    # Any-to-any permit blocks all traffic — always dangerous
    if (rule.action == Action.PERMIT
            and rule.source_is_any
            and rule.destination_is_any
            and rule.protocol == Protocol.IP
            and not rule.dst_ports):
        errors.append(
            "SAFETY_ANY_TO_ANY_PERMIT: Permitting all IP traffic from any source to any "
            "destination is blocked. Specify at least a source or destination."
        )

    # Broad IP permit with any source or any destination
    if rule.action == Action.PERMIT:
        broad = rule.protocol == Protocol.IP and not rule.dst_ports
        if broad and (rule.source_is_any or rule.destination_is_any):
            errors.append(
                "SAFETY_BROAD_PERMIT: Permitting all IP traffic with any source or any "
                "destination is too permissive. Restrict the protocol/port or both endpoints."
            )

    # Low confidence on a permit is risky — could open unintended access
    if rule.action == Action.PERMIT and rule.confidence < 0.5:
        errors.append(
            f"SAFETY_LOW_CONFIDENCE_PERMIT: LLM confidence {rule.confidence:.2f} is too low "
            "for a permit rule. Clarify the intent before proceeding."
        )

    # No interfaces defined — cannot deploy
    if len(rule.interfaces) == 0:
        errors.append(
            "SAFETY_NO_INTERFACE: No deployment interface defined. "
            "The rule cannot be applied to any interface."
        )

    safe = len(errors) == 0
    return SafetyResult(
        safe=safe,
        errors=errors,
        message="All safety checks passed" if safe else f"{len(errors)} safety violation(s)"
    )