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

    assert data["ai_analysis"] is not None
    assert data["ai_analysis"]["risk_assessment"] == "CRITICAL"
    assert data["ai_analysis"]["confidence"] == 1.0
    assert "Shell access detected" in data["ai_analysis"]["concerns"]