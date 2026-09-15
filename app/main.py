from fastapi import FastAPI

from app.models import ToolDefinition
from app.scanners.tool_scanner import scan_tool


app = FastAPI(
    title="Agent Guard",
    description="Security scanner for AI agents and tools.",
    version="0.1.0"
)


@app.get("/")
def health_check():
    return {
        "name": "Agent Guard",
        "status": "running",
        "version": "0.1.0"
    }


@app.post("/scan")
def scan(tool: ToolDefinition):
    findings = scan_tool(tool)

    return {
        "tool": tool,
        "findings": findings,
        "total_findings": len(findings)
    }