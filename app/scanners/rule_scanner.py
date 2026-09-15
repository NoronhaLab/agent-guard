DANGEROUS_KEYWORDS = {
    "delete": {
        "message": "Operação destrutiva detectada.",
        "severity": "HIGH",
        "points": 30,
    },
    "remove": {
        "message": "Operação destrutiva detectada.",
        "severity": "HIGH",
        "points": 30,
    },
    "execute": {
        "message": "Capacidade de execução detectada.",
        "severity": "HIGH",
        "points": 30,
    },
    "shell": {
        "message": "Acesso ao shell detectado.",
        "severity": "CRITICAL",
        "points": 40,
    },
    "admin": {
        "message": "Capacidade administrativa detectada.",
        "severity": "HIGH",
        "points": 25,
    },
    "password": {
        "message": "Possível manipulação de credenciais detectada.",
        "severity": "HIGH",
        "points": 25,
    },
    "token": {
        "message": "Possível manipulação de tokens detectada.",
        "severity": "HIGH",
        "points": 25,
    },
    "secret": {
        "message": "Possível manipulação de segredos detectada.",
        "severity": "HIGH",
        "points": 25,
    },
    "payment": {
        "message": "Operação financeira detectada.",
        "severity": "HIGH",
        "points": 25,
    },
}


def scan_text(text: str) -> list[dict]:
    text = text.lower()

    findings = []

    for keyword, rule in DANGEROUS_KEYWORDS.items():
        if keyword in text:
            findings.append(
                {
                    "keyword": keyword,
                    "message": rule["message"],
                    "severity": rule["severity"],
                    "points": rule["points"],
                }
            )

    return findings