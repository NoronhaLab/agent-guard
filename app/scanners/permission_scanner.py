from app.models import Finding


DANGEROUS_PERMISSIONS = {
    "database_delete": {
        "id": "AG009",
        "category": "excessive_permissions",
        "title": "Database delete permission detected",
        "description": (
            "The tool has permission to delete records from a database."
        ),
        "recommendation": (
            "Remove delete access unless it is strictly required "
            "for the tool's purpose."
        ),
        "severity": "CRITICAL",
        "points": 40,
    },
    "database_write": {
        "id": "AG010",
        "category": "excessive_permissions",
        "title": "Database write permission detected",
        "description": (
            "The tool has permission to modify records in a database."
        ),
        "recommendation": (
            "Use the minimum database privileges required by the tool."
        ),
        "severity": "HIGH",
        "points": 25,
    },
    "database_read": {
        "id": "AG011",
        "category": "data_access",
        "title": "Database read permission detected",
        "description": (
            "The tool can read information from a database."
        ),
        "recommendation": (
            "Restrict database access to only the required data."
        ),
        "severity": "MEDIUM",
        "points": 10,
    },
    "external_http": {
        "id": "AG012",
        "category": "external_communication",
        "title": "External HTTP access detected",
        "description": (
            "The tool can communicate with external HTTP endpoints."
        ),
        "recommendation": (
            "Restrict outbound connections to approved destinations."
        ),
        "severity": "HIGH",
        "points": 25,
    },
}


def scan_permissions(permissions: list[str]) -> list[Finding]:
    findings = []

    for permission in permissions:
        rule = DANGEROUS_PERMISSIONS.get(permission)

        if rule:
            findings.append(Finding(**rule))

    return findings