from app.scanners.permission_scanner import scan_permissions


def test_detects_database_delete():
    findings = scan_permissions(["database_delete"])

    ids = {
        finding.id
        for finding in findings
    }

    assert "AG009" in ids


def test_detects_database_read():
    findings = scan_permissions(["database_read"])

    ids = {
        finding.id
        for finding in findings
    }

    assert "AG011" in ids


def test_safe_permissions_have_no_findings():
    findings = scan_permissions([])

    assert findings == []