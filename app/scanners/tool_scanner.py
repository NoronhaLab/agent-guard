from app.models import ToolDefinition, Finding
from app.scanners.rule_scanner import scan_text


def scan_tool(tool: ToolDefinition) -> list[Finding]:
    text_to_scan = (
        f"{tool.name} "
        f"{tool.description} "
        f"{' '.join(tool.permissions)}"
    )

    raw_findings = scan_text(text_to_scan)

    return [
        Finding(**finding)
        for finding in raw_findings
    ]