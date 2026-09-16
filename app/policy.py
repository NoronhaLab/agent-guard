from pydantic import BaseModel, Field


class SecurityPolicy(BaseModel):
    name: str = "default"

    block_critical: bool = True

    require_human_approval_for: list[str] = Field(
        default_factory=list
    )

    blocked_permissions: list[str] = Field(
        default_factory=list
    )