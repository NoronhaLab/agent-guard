import pytest
from pydantic import ValidationError

from app.decision_engine import make_decision
from app.models import PolicyResult

from app.policy import SecurityPolicy


def test_decision_blocks_when_policy_blocks():
    policy = PolicyResult(
        policy="default",
        blocked=True,
        approval_required=[],
        blocked_permissions=[],
        reasons=["Critical security findings detected."],
    )

    decision = make_decision(policy)

    assert decision.action == "BLOCK"
    assert decision.reason == "Critical security findings detected."


def test_decision_requires_approval_when_needed():
    policy = PolicyResult(
        policy="default",
        blocked=False,
        approval_required=["database_write"],
        blocked_permissions=[],
        reasons=[],
    )

    decision = make_decision(policy)

    assert decision.action == "REQUIRE_APPROVAL"
    assert decision.reason == "Human approval required for permissions: database_write."


def test_decision_allows_safe_tool():
    policy = PolicyResult(
        policy="default",
        blocked=False,
        approval_required=[],
        blocked_permissions=[],
        reasons=[],
    )

    decision = make_decision(policy)

    assert decision.action == "ALLOW"
    assert decision.reason == (
    "No blocking policy or human approval requirement was triggered."
)

def test_decision_rejects_invalid_action():
    from app.models import DecisionResult

    with pytest.raises(ValidationError):
        DecisionResult(
            action="INVALID_ACTION",
            reason="This action should not be accepted.",
        )

def test_block_has_priority_over_human_approval():
    policy = PolicyResult(
        policy="default",
        blocked=True,
        approval_required=["shell"],
        blocked_permissions=[],
        reasons=["Critical security findings detected."],
    )

    decision = make_decision(policy)

    assert decision.action == "BLOCK"
    assert decision.reason == "Critical security findings detected."


def test_decision_accepts_risk_level():
    policy = PolicyResult(
        policy="default",
        blocked=False,
        approval_required=[],
        blocked_permissions=[],
        reasons=[],
    )

    decision = make_decision(
        policy,
        risk_level="LOW",
    )

    assert decision.action == "ALLOW" 

def test_high_risk_requires_approval_when_policy_allows():
    policy = PolicyResult(
        policy="default",
        blocked=False,
        approval_required=[],
        blocked_permissions=[],
        reasons=[],
    )

    decision = make_decision(
        policy,
        risk_level="HIGH",
    )

    assert decision.action == "REQUIRE_APPROVAL"
    assert decision.reason == "High-risk tool requires human approval."

def test_critical_risk_blocks_when_policy_allows():
    policy = PolicyResult(
        policy="default",
        blocked=False,
        approval_required=[],
        blocked_permissions=[],
        reasons=[],
    )

    decision = make_decision(
        policy,
        risk_level="CRITICAL",
    )

    assert decision.action == "BLOCK"
    assert decision.reason == "Critical-risk tool cannot be automatically allowed."

def test_critical_risk_has_priority_over_approval():
    policy = PolicyResult(
        policy="default",
        blocked=False,
        approval_required=["database_write"],
        blocked_permissions=[],
        reasons=[],
    )

    decision = make_decision(
        policy,
        risk_level="CRITICAL",
    )

    assert decision.action == "BLOCK"
    assert decision.reason == "Critical-risk tool cannot be automatically allowed."

def test_custom_policy_can_block_high_risk():
    policy = PolicyResult(
        policy="strict",
        blocked=False,
        approval_required=[],
        blocked_permissions=[],
        reasons=[],
    )

    security_policy = SecurityPolicy(
        name="strict",
        block_risk_levels=["HIGH", "CRITICAL"],
        require_approval_risk_levels=[],
    )

    decision = make_decision(
        policy,
        risk_level="HIGH",
        security_policy=security_policy,
    )

    assert decision.action == "BLOCK"
    assert decision.reason == "Risk level HIGH is blocked by security policy 'strict'."

def test_custom_policy_can_require_approval_for_medium_risk():
    policy = PolicyResult(
        policy="cautious",
        blocked=False,
        approval_required=[],
        blocked_permissions=[],
        reasons=[],
    )

    security_policy = SecurityPolicy(
        name="cautious",
        block_risk_levels=["CRITICAL"],
        require_approval_risk_levels=["MEDIUM", "HIGH"],
    )

    decision = make_decision(
        policy,
        risk_level="MEDIUM",
        security_policy=security_policy,
    )

    assert decision.action == "REQUIRE_APPROVAL"
    assert decision.reason == (
        "Risk level MEDIUM requires human approval "
        "under security policy 'cautious'."
    )   

def test_block_risk_level_has_priority_over_approval_risk_level():
    policy = PolicyResult(
        policy="conflicting",
        blocked=False,
        approval_required=[],
        blocked_permissions=[],
        reasons=[],
    )

    security_policy = SecurityPolicy(
        name="conflicting",
        block_risk_levels=["HIGH"],
        require_approval_risk_levels=["HIGH"],
    )

    decision = make_decision(
        policy,
        risk_level="HIGH",
        security_policy=security_policy,
    )

    assert decision.action == "BLOCK"
    assert decision.reason == (
        "Risk level HIGH is blocked by "
        "security policy 'conflicting'."
    )

def test_custom_policy_can_allow_high_risk():
    policy = PolicyResult(
        policy="development",
        blocked=False,
        approval_required=[],
        blocked_permissions=[],
        reasons=[],
    )

    security_policy = SecurityPolicy(
        name="development",
        block_risk_levels=[],
        require_approval_risk_levels=[],
    )

    decision = make_decision(
        policy,
        risk_level="HIGH",
        security_policy=security_policy,
    )

    assert decision.action == "ALLOW"
    assert decision.reason == (
        "No blocking policy or human approval requirement was triggered."
    )        