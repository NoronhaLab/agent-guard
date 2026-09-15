from app.scanners.sensitive_data_scanner import scan_sensitive_data


def test_detects_email():
    findings = scan_sensitive_data(
        "Contact me at carlos@example.com"
    )

    ids = {
        finding.id
        for finding in findings
    }

    assert "AG016" in ids


def test_detects_cpf():
    findings = scan_sensitive_data(
        "CPF: 123.456.789-00"
    )

    ids = {
        finding.id
        for finding in findings
    }

    assert "AG017" in ids


def test_safe_text_has_no_sensitive_data():
    findings = scan_sensitive_data(
        "Get weather information"
    )

    assert findings == []