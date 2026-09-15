from app.models import ToolDefinition, Finding
from app.scanners.rule_scanner import scan_text
from app.scanners.permission_scanner import scan_permissions
from app.scanners.permission_analyzer import analyze_permissions
from app.scanners.sensitive_data_scanner import scan_sensitive_data


def scan_tool(tool: ToolDefinition) -> list[Finding]:
    text_to_scan = (
        f"{tool.name} "
        f"{tool.description} "
        f"{' '.join(tool.permissions)}"
    )

    text_findings = scan_text(text_to_scan)

    permission_findings = scan_permissions(
        tool.permissions
    )

    permission_analysis_findings = analyze_permissions(
        tool.description,
        tool.permissions,
    )

    sensitive_data_findings = scan_sensitive_data(
        tool.description
    )

    return (
        [
            Finding(**finding)
            for finding in text_findings
        ]
        + permission_findings
        + permission_analysis_findings
        + sensitive_data_findings
    )