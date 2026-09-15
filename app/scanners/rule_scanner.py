DANGEROUS_KEYWORDS = {
    "delete": {
        "id": "AG001",
        "category": "destructive_operation",
        "title": "Destructive operation detected",
        "description": "The tool appears capable of deleting data or resources.",
        "recommendation": (
            "Require explicit authorization before destructive operations."
        ),
        "severity": "HIGH",
        "points": 30,
    },
    "remove": {
        "id": "AG001",
        "category": "destructive_operation",
        "title": "Destructive operation detected",
        "description": "The tool appears capable of removing data or resources.",
        "recommendation": (
            "Require explicit authorization before destructive operations."
        ),
        "severity": "HIGH",
        "points": 30,
    },
    "execute": {
        "id": "AG002",
        "category": "command_execution",
        "title": "Command execution capability detected",
        "description": "The tool may execute commands or actions on the host system.",
        "recommendation": (
            "Restrict command execution and require approval for sensitive actions."
        ),
        "severity": "HIGH",
        "points": 30,
    },
    "shell": {
        "id": "AG003",
        "category": "dangerous_capability",
        "title": "Shell access detected",
        "description": "The tool appears to have access to a system shell.",
        "recommendation": (
            "Restrict shell access to the minimum required capability "
            "and require human approval when appropriate."
        ),
        "severity": "CRITICAL",
        "points": 40,
    },
    "admin": {
        "id": "AG004",
        "category": "excessive_privilege",
        "title": "Administrative capability detected",
        "description": "The tool appears to have administrative privileges.",
        "recommendation": (
            "Apply least privilege and avoid administrative permissions "
            "unless strictly required."
        ),
        "severity": "HIGH",
        "points": 25,
    },
    "password": {
        "id": "AG005",
        "category": "credential_handling",
        "title": "Credential handling detected",
        "description": "The tool may handle passwords or authentication credentials.",
        "recommendation": (
            "Avoid exposing credentials to the agent and use secure secret storage."
        ),
        "severity": "HIGH",
        "points": 25,
    },
    "token": {
        "id": "AG006",
        "category": "credential_handling",
        "title": "Token handling detected",
        "description": "The tool may handle authentication or access tokens.",
        "recommendation": (
            "Keep tokens outside model-visible context and restrict access."
        ),
        "severity": "HIGH",
        "points": 25,
    },
    "secret": {
        "id": "AG007",
        "category": "sensitive_data",
        "title": "Secret handling detected",
        "description": "The tool may expose or manipulate sensitive secrets.",
        "recommendation": (
            "Use secure secret management and prevent secrets from entering "
            "model-visible context."
        ),
        "severity": "HIGH",
        "points": 25,
    },
    "payment": {
        "id": "AG008",
        "category": "financial_operation",
        "title": "Financial operation detected",
        "description": "The tool appears capable of performing financial actions.",
        "recommendation": (
            "Require explicit authorization and strong controls for financial actions."
        ),
        "severity": "HIGH",
        "points": 25,
    },
}


def scan_text(text: str) -> list[dict]:
    text = text.lower()

    findings = []

    for keyword, rule in DANGEROUS_KEYWORDS.items():
        if keyword in text:
            findings.append(rule)

    return findings