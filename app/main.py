from fastapi import FastAPI

from app.models import ToolDefinition, ScanResult
from app.risk_engine import calculate_risk_level, calculate_score
from app.scanners.tool_scanner import scan_tool


app = FastAPI(
    title="Agent Guard",
    description="Security scanner for AI agents and tools.",
    version="0.2.0"
)


@app.get("/")
def health_check():
    return {
        "name": "Agent Guard",
        "status": "running",
        "version": "0.2.0"
    }


@app.post("/scan", response_model=ScanResult)
def scan(tool: ToolDefinition):
    findings = scan_tool(tool)

    score = calculate_score(
        [finding.model_dump() for finding in findings]
    )

    risk_level = calculate_risk_level(
    score,
    [finding.model_dump() for finding in findings]
)

    return ScanResult(
        tool=tool,
        findings=findings,
        score=score,
        risk_level=risk_level
    )