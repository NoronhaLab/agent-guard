from app.models import Finding
from app.risk_correlator import correlate_findings


def test_detects_compound_delete_risk():
    findings = [
        Finding(
            id="AG009",
            category="excessive_permissions",
            title="Database delete permission detected",
            description="Test",
            recommendation="Test",
            severity="CRITICAL",
            points=40,
        ),
        Finding(
            id="AG013",
            category="excessive_permissions",
            title="Database delete permission may be excessive",
            description="Test",
            recommendation="Test",
            severity="CRITICAL",
            points=40,
        ),
    ]

    result = correlate_findings(findings)

    ids = {
        finding.id
        for finding in result
    }

    assert "AG018" in ids


def test_no_compound_risk_without_excessive_delete():
    findings = [
        Finding(
            id="AG009",
            category="excessive_permissions",
            title="Database delete permission detected",
            description="Test",
            recommendation="Test",
            severity="CRITICAL",
            points=40,
        )
    ]

    result = correlate_findings(findings)

    ids = {
        finding.id
        for finding in result
    }

    assert "AG018" not in ids