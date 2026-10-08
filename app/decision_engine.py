from app.models import DecisionResult, PolicyResult, RiskLevel
from app.policy import SecurityPolicy   


def make_decision(
    policy: PolicyResult,
    risk_level: RiskLevel | None = None,
    security_policy: SecurityPolicy | None = None,
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

    if (
       security_policy is not None
       and risk_level is not None
       and risk_level in security_policy.block_risk_levels
):
        return DecisionResult(
          action="BLOCK",
          reason=(
            f"Risk level {risk_level} is blocked by "
            f"security policy '{security_policy.name}'."
          ),
      )

    if (
       security_policy is not None
       and risk_level is not None
       and risk_level in security_policy.require_approval_risk_levels
):
        return DecisionResult(
          action="REQUIRE_APPROVAL",
          reason=(
            f"Risk level {risk_level} requires human approval "
            f"under security policy '{security_policy.name}'."
        ),
    )

    if security_policy is None and risk_level == "CRITICAL":
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

    if security_policy is None and risk_level == "HIGH":
        return DecisionResult(
            action="REQUIRE_APPROVAL",
            reason="High-risk tool requires human approval.",
        )

    return DecisionResult(
        action="ALLOW",
        reason="No blocking policy or human approval requirement was triggered.",
    )