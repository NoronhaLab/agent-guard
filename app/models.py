from pydantic import BaseModel


class ScanRequest(BaseModel):
    text: str