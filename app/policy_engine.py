from app.models import Finding
from app.policy import SecurityPolicy


def evaluate_policy(
    findings: list[Finding],
    permissions: list[str],
    policy: SecurityPolicy,
) -> dict:

    critical_findings = [
        finding
        for finding in findings
        if finding.severity == "CRITICAL"
    ]

    blocked_permissions = [
        permission
        for permission in permissions
        if permission in policy.blocked_permissions
    ]

    approvals_required = [
        permission
        for permission in permissions
        if permission in policy.require_human_approval_for
    ]

    blocked = False

    reasons = []

    if policy.block_critical and critical_findings:
        blocked = True
        reasons.append(
            "Critical security findings detected."
        )

    if blocked_permissions:
        blocked = True
        reasons.append(
            "One or more permissions are blocked by policy."
        )

    return {
        "policy": policy.name,
        "blocked": blocked,
        "approval_required": approvals_required,
        "blocked_permissions": blocked_permissions,
        "reasons": reasons,
    }