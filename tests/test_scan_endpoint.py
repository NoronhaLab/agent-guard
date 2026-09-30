import pytest
from pydantic import ValidationError

from app.models import ScanResult

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_scan_endpoint_returns_complete_security_analysis():
    response = client.post(
        "/scan",
        json={
            "name": "execute_command",
            "description": "Execute shell commands on the server",
            "permissions": ["shell", "system"],
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["tool"]["name"] == "execute_command"

    assert data["score"] == 70
    assert data["risk_level"] == "CRITICAL"

    finding_ids = [
        finding["id"]
        for finding in data["findings"]
    ]

    assert "AG002" in finding_ids
    assert "AG003" in finding_ids

    assert data["policy"]["blocked"] is True
    assert "shell" in data["policy"]["approval_required"]

    assert data["decision"]["action"] == "BLOCK"
    assert data["decision"]["reason"] == "Critical security findings detected."

    assert data["ai_analysis"] is not None
    assert data["ai_analysis"]["risk_assessment"] == "CRITICAL"
    assert data["ai_analysis"]["confidence"] == 1.0
    assert "Shell access detected" in data["ai_analysis"]["concerns"]

def test_scan_endpoint_survives_ai_failure(monkeypatch):
    def fake_ai_failure(*args, **kwargs):
        raise RuntimeError("AI service unavailable")

    monkeypatch.setattr(
        "app.main.analyze_tool_with_ai",
        fake_ai_failure,
    )

    response = client.post(
        "/scan",
        json={
            "name": "execute_command",
            "description": "Execute shell commands on the server",
            "permissions": ["shell", "system"],
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["score"] == 70
    assert data["risk_level"] == "CRITICAL"

    assert data["policy"]["blocked"] is True

    assert data["ai_analysis"] is None

def test_scan_result_rejects_invalid_risk_level():
    with pytest.raises(ValidationError):
        ScanResult(
            tool={
                "name": "safe_tool",
                "description": "Safe test tool",
                "permissions": [],
            },
            findings=[],
            score=0,
            risk_level="INVALID",
            policy={
                "policy": "default",
                "blocked": False,
                "approval_required": [],
                "blocked_permissions": [],
                "reasons": [],
            },
            ai_analysis=None,
            decision={
                "action": "ALLOW",
                "reason": "No blocking policy or human approval requirement was triggered.",
            },
        )