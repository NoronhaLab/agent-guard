from app.scanners.rule_scanner import scan_text


def test_detects_shell():
    findings = scan_text("Execute shell command")

    ids = {
        finding["id"]
        for finding in findings
    }

    assert "AG003" in ids


def test_detects_admin():
    findings = scan_text("Run command as admin")

    ids = {
        finding["id"]
        for finding in findings
    }

    assert "AG004" in ids


def test_safe_text_has_no_findings():
    findings = scan_text("Get weather information")

    assert findings == []