from app.risk_engine import calculate_score, calculate_risk_level


def test_score_is_calculated():
    findings = [
        {"points": 30},
        {"points": 40},
    ]

    assert calculate_score(findings) == 70


def test_critical_finding_forces_critical_risk():
    findings = [
        {
            "severity": "CRITICAL",
            "points": 40,
        }
    ]

    score = calculate_score(findings)
    risk = calculate_risk_level(score, findings)

    assert score == 40
    assert risk == "CRITICAL"


def test_zero_findings_are_low_risk():
    findings = []

    score = calculate_score(findings)
    risk = calculate_risk_level(score, findings)

    assert score == 0
    assert risk == "LOW"