import logging

from fastapi import FastAPI

from app.models import ToolDefinition, ScanResult
from app.risk_engine import calculate_risk_level, calculate_score
from app.scanners.tool_scanner import scan_tool
from app.finding_manager import deduplicate_findings
from app.risk_correlator import correlate_findings
from app.policy import SecurityPolicy
from app.policy_engine import evaluate_policy
from app.services.ai_analyzer import analyze_tool_with_ai

logger = logging.getLogger(__name__)


app = FastAPI(
    title="Agent Guard",
    description="Security scanner for AI agents and tools.",
    version="0.2.0"
)


DEFAULT_POLICY = SecurityPolicy(
    name="default",
    block_critical=True,
    require_human_approval_for=[
        "database_delete",
        "shell",
    ],
    blocked_permissions=[]
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

    findings = deduplicate_findings(findings)

    findings = correlate_findings(findings)

    score = calculate_score(
        [finding.model_dump() for finding in findings]
    )

    risk_level = calculate_risk_level(
        score,
        [finding.model_dump() for finding in findings]
    )

    policy_result = evaluate_policy(
        findings,
        tool.permissions,
        DEFAULT_POLICY
    )

    try:
        ai_analysis = analyze_tool_with_ai(
            name=tool.name,
            description=tool.description,
            permissions=tool.permissions,
            findings=[
                finding.model_dump()
                for finding in findings
            ],
        )
    except Exception:
        logger.exception(
            "AI analysis failed. Continuing with deterministic analysis."
        )
        ai_analysis = None

    return {
        "tool": tool,
        "findings": findings,
        "score": score,
        "risk_level": risk_level,
        "policy": policy_result,
        "ai_analysis": ai_analysis,
    }