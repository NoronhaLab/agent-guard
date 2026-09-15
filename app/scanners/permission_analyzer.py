from app.models import Finding


PERMISSION_REQUIREMENTS = {
    "database_read": {
        "keywords": [
            "read",
            "search",
            "find",
            "list",
            "view",
            "get",
            "consulta",
            "consultar",
            "buscar",
            "listar",
            "visualizar",
        ],
        "required_permission": "database_read",
    },
    "database_write": {
        "keywords": [
            "create",
            "update",
            "edit",
            "write",
            "insert",
            "modify",
            "criar",
            "atualizar",
            "editar",
            "alterar",
        ],
        "required_permission": "database_write",
    },
    "database_delete": {
        "keywords": [
            "delete",
            "remove",
            "erase",
            "destroy",
            "apagar",
            "excluir",
            "remover",
        ],
        "required_permission": "database_delete",
    },
}


def analyze_permissions(
    description: str,
    permissions: list[str],
) -> list[Finding]:

    description_lower = description.lower()

    findings = []

    for permission, rule in PERMISSION_REQUIREMENTS.items():

        if permission not in permissions:
            continue

        keywords = rule["keywords"]

        purpose_matches_permission = any(
            keyword in description_lower
            for keyword in keywords
        )

        if purpose_matches_permission:
            continue

        if permission == "database_delete":
            findings.append(
                Finding(
                    id="AG013",
                    category="excessive_permissions",
                    title="Database delete permission may be excessive",
                    description=(
                        "The tool has database delete permission, "
                        "but its description does not clearly indicate "
                        "that deleting records is part of its purpose."
                    ),
                    recommendation=(
                        "Remove database delete permission unless "
                        "deletion is explicitly required."
                    ),
                    severity="CRITICAL",
                    points=40,
                )
            )

        elif permission == "database_write":
            findings.append(
                Finding(
                    id="AG014",
                    category="excessive_permissions",
                    title="Database write permission may be excessive",
                    description=(
                        "The tool has database write permission, "
                        "but its description does not clearly indicate "
                        "that modifying records is part of its purpose."
                    ),
                    recommendation=(
                        "Remove write access unless the tool "
                        "must modify database records."
                    ),
                    severity="HIGH",
                    points=25,
                )
            )

    return findings