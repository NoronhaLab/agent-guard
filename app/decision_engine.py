from app.models import DecisionResult, PolicyResult


def make_decision(policy: PolicyResult) -> DecisionResult:
    if policy.blocked:
        reason = (
            "; ".join(policy.reasons)
            if policy.reasons
            else "Security policy blocked this tool."
        )

        return DecisionResult(
            action="BLOCK",
            reason=reason,
        )

    if policy.approval_required:
        return DecisionResult(
            action="REQUIRE_APPROVAL",
            reason="Human approval is required before this tool can be used.",
        )

    return DecisionResult(
        action="ALLOW",
        reason="No blocking policy or human approval requirement was triggered.",
    )
