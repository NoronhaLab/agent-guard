from pydantic import BaseModel, Field
from typing import Literal


class ToolDefinition(BaseModel):
    name: str
    description: str
    permissions: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    id: str
    category: str
    title: str
    description: str
    recommendation: str
    severity: str
    points: int


class PolicyResult(BaseModel):
    policy: str
    blocked: bool
    approval_required: list[str]
    blocked_permissions: list[str]
    reasons: list[str]

class DecisionResult(BaseModel):
    action: Literal["ALLOW", "REQUIRE_APPROVAL", "BLOCK"]
    reason: str

class AIAnalysis(BaseModel):
    summary: str
    risk_assessment: str
    confidence: float
    concerns: list[str]
    recommendations: list[str]


class ScanResult(BaseModel):
    tool: ToolDefinition
    findings: list[Finding]
    score: int
    risk_level: str
    policy: PolicyResult
    ai_analysis: AIAnalysis | None = None
    decision: DecisionResult | None = None