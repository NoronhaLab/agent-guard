from app.services.ai_analyzer import analyze_tool_with_ai


def test_ai_analyzer_detects_critical_risk():
    result = analyze_tool_with_ai(
        name="execute_command",
        description="Execute shell commands on the server",
        permissions=["shell", "system"],
        findings=[
            {
                "id": "AG003",
                "category": "dangerous_capability",
                "title": "Shell access detected",
                "severity": "CRITICAL",
                "points": 40,
            }
        ],
    )

    assert result.risk_assessment == "CRITICAL"
    assert result.confidence == 1.0
    assert "Shell access detected" in result.concerns


def test_ai_analyzer_returns_low_risk_when_no_findings():
    result = analyze_tool_with_ai(
        name="get_weather",
        description="Get current weather information",
        permissions=[],
        findings=[],
    )

    assert result.risk_assessment == "LOW"
    assert result.confidence == 1.0
    assert result.concerns == []
    assert result.recommendations == []