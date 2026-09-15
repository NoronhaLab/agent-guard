from app.models import Finding


def correlate_findings(
    findings: list[Finding],
) -> list[Finding]:
    correlated = list(findings)

    categories = {
        finding.category
        for finding in findings
    }

    has_delete_permission = any(
        finding.id == "AG009"
        for finding in findings
    )

    has_excessive_delete = any(
        finding.id == "AG013"
        for finding in findings
    )

    if has_delete_permission and has_excessive_delete:
        correlated.append(
            Finding(
                id="AG018",
                category="compound_risk",
                title="Potential high-impact autonomous deletion",
                description=(
                    "The tool has database delete permission and the "
                    "permission may exceed the purpose described for the tool."
                ),
                recommendation=(
                    "Require explicit authorization or human approval "
                    "before allowing destructive database operations."
                ),
                severity="CRITICAL",
                points=0,
            )
        )

    return correlated