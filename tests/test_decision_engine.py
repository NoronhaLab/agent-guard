import pytest
from pydantic import ValidationError

from app.decision_engine import make_decision
from app.models import PolicyResult


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

def test_decision_rejects_invalid_action():
    from app.models import DecisionResult

    with pytest.raises(ValidationError):
        DecisionResult(
            action="INVALID_ACTION",
            reason="This action should not be accepted.",
        )    