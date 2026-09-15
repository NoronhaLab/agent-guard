SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def calculate_score(findings: list[dict]) -> int:
    score = sum(finding["points"] for finding in findings)

    return min(score, 100)


def calculate_risk_level(score: int, findings: list[dict]) -> str:
    severities = {
        finding["severity"]
        for finding in findings
    }

    if "CRITICAL" in severities:
        return "CRITICAL"

    if score >= 75:
        return "CRITICAL"

    if score >= 50:
        return "HIGH"

    if score >= 25:
        return "MEDIUM"

    return "LOW"