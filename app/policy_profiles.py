from app.policy import SecurityPolicy


def get_security_policy(profile: str) -> SecurityPolicy:
    if profile == "default":
        return SecurityPolicy(
            name="default",
            block_critical=True,
            block_risk_levels=["CRITICAL"],
            require_approval_risk_levels=["HIGH"],
            require_human_approval_for=[
              "database_delete",
              "shell",
            ],
            blocked_permissions=[],
    )

    if profile == "strict":
        return SecurityPolicy(
            name="strict",
            block_risk_levels=["HIGH", "CRITICAL"],
            require_approval_risk_levels=["MEDIUM"],
        )

    if profile == "development":
        return SecurityPolicy(
            name="development",
            block_risk_levels=[],
            require_approval_risk_levels=[],
        )

    raise ValueError(
        f"Unknown security policy profile: {profile}"
    )