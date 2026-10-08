from pydantic import BaseModel, Field

from app.models import RiskLevel


class SecurityPolicy(BaseModel):
    name: str = "default"

    block_critical: bool = True

    block_risk_levels: list[RiskLevel] = Field(
        default_factory=lambda: ["CRITICAL"]
    )

    require_approval_risk_levels: list[RiskLevel] = Field(
        default_factory=lambda: ["HIGH"]
    )

    require_human_approval_for: list[str] = Field(
        default_factory=list
    )

    blocked_permissions: list[str] = Field(
        default_factory=list
    )