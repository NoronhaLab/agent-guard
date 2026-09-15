from pydantic import BaseModel, Field


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


class ScanResult(BaseModel):
    tool: ToolDefinition
    findings: list[Finding]
    score: int
    risk_level: str