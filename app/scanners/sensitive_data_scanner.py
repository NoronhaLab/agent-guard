import re

from app.models import Finding


PATTERNS = {
    "api_key": {
        "pattern": r"\b(?:sk|pk)_[A-Za-z0-9_-]{16,}\b",
        "id": "AG015",
        "category": "sensitive_data",
        "title": "Possible API key detected",
        "description": (
            "The input appears to contain a possible API key."
        ),
        "recommendation": (
            "Never expose API keys to the model or store them in tool input."
        ),
        "severity": "CRITICAL",
        "points": 40,
    },
    "email": {
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "id": "AG016",
        "category": "personal_data",
        "title": "Possible email address detected",
        "description": (
            "The input appears to contain an email address."
        ),
        "recommendation": (
            "Limit exposure of personal data and only process it when necessary."
        ),
        "severity": "MEDIUM",
        "points": 10,
    },
    "cpf": {
        "pattern": r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b",
        "id": "AG017",
        "category": "personal_data",
        "title": "Possible CPF detected",
        "description": (
            "The input appears to contain a Brazilian CPF number."
        ),
        "recommendation": (
            "Minimize exposure of personal identifiers and apply appropriate access controls."
        ),
        "severity": "HIGH",
        "points": 25,
    },
}


def scan_sensitive_data(text: str) -> list[Finding]:
    findings = []

    for rule in PATTERNS.values():
        if re.search(rule["pattern"], text):
            findings.append(
                Finding(
                    id=rule["id"],
                    category=rule["category"],
                    title=rule["title"],
                    description=rule["description"],
                    recommendation=rule["recommendation"],
                    severity=rule["severity"],
                    points=rule["points"],
                )
            )

    return findings