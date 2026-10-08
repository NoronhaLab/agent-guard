import pytest

from app.policy_profiles import get_security_policy


def test_default_policy_profile():
    policy = get_security_policy("default")

    assert policy.name == "default"
    assert policy.block_risk_levels == ["CRITICAL"]
    assert policy.require_approval_risk_levels == ["HIGH"]
    assert policy.block_critical is True
    assert policy.require_human_approval_for == [
        "database_delete",
        "shell",
    ]


def test_strict_policy_profile():
    policy = get_security_policy("strict")

    assert policy.name == "strict"
    assert policy.block_risk_levels == ["HIGH", "CRITICAL"]
    assert policy.require_approval_risk_levels == ["MEDIUM"]


def test_development_policy_profile():
    policy = get_security_policy("development")

    assert policy.name == "development"
    assert policy.block_risk_levels == []
    assert policy.require_approval_risk_levels == []


def test_unknown_policy_profile_raises_error():
    with pytest.raises(ValueError):
        get_security_policy("unknown")