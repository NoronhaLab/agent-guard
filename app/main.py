from fastapi import FastAPI

from app.models import ScanRequest
from app.scanners.rule_scanner import scan_text


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
def scan(request: ScanRequest):
    findings = scan_text(request.text)

    return {
        "text": request.text,
        "findings": findings,
        "total_findings": len(findings)
    }