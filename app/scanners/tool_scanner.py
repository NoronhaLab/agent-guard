from app.models import ToolDefinition
from app.scanners.rule_scanner import scan_text


def scan_tool(tool: ToolDefinition) -> list[str]:
    text_to_scan = (
        f"{tool.name} "
        f"{tool.description} "
        f"{' '.join(tool.permissions)}"
    )

    return scan_text(text_to_scan)