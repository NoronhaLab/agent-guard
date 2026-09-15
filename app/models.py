from pydantic import BaseModel, Field


class ToolDefinition(BaseModel):
    name: str
    description: str
    permissions: list[str] = Field(default_factory=list)