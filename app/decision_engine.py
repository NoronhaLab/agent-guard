from app.models import DecisionResult, PolicyResult


def make_decision(
    policy: PolicyResult,
    risk_level: str | None = None,
) -> DecisionResult:
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

    if risk_level == "CRITICAL":
        return DecisionResult(
            action="BLOCK",
            reason="Critical-risk tool cannot be automatically allowed.",
        )

    if policy.approval_required:
        permissions = ", ".join(policy.approval_required)

        return DecisionResult(
            action="REQUIRE_APPROVAL",
            reason=f"Human approval required for permissions: {permissions}.",
        )

    if risk_level == "HIGH":
        return DecisionResult(
            action="REQUIRE_APPROVAL",
            reason="High-risk tool requires human approval.",
        )

    return DecisionResult(
        action="ALLOW",
        reason="No blocking policy or human approval requirement was triggered.",
    )