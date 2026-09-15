DANGEROUS_KEYWORDS = {
    "delete": "Operação destrutiva detectada.",
    "remove": "Operação destrutiva detectada.",
    "execute": "Capacidade de execução detectada.",
    "shell": "Acesso ao shell detectado.",
    "admin": "Capacidade administrativa detectada.",
    "password": "Possível manipulação de credenciais detectada.",
    "token": "Possível manipulação de tokens detectada.",
    "secret": "Possível manipulação de segredos detectada.",
    "payment": "Operação financeira detectada.",
}


def scan_text(text: str) -> list[str]:
    """
    Analisa um texto e retorna os riscos encontrados.
    """

    text = text.lower()

    findings = []

    for keyword, message in DANGEROUS_KEYWORDS.items():
        if keyword in text:
            findings.append(message)

    return findings