from app.models import Finding


def deduplicate_findings(
    findings: list[Finding],
) -> list[Finding]:
    unique = {}

    for finding in findings:
        key = (
            finding.category,
            finding.title,
        )

        unique[key] = finding

    return list(unique.values())