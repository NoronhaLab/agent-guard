import os

from dotenv import load_dotenv
from openai import OpenAI

from app.models import AIAnalysis


load_dotenv()


SYSTEM_PROMPT = """
You are an AI security auditor for AI agents and tools.

Analyze the provided tool using only the information supplied.

Look for:

- excessive agency
- excessive permissions
- dangerous capabilities
- sensitive data exposure
- missing authorization
- missing human approval

Do not invent vulnerabilities.

Return a structured security assessment.

The confidence value must be between 0 and 1.

The risk_assessment must be one of:
LOW, MEDIUM, HIGH, CRITICAL.
"""


def analyze_tool_with_mock(
    name: str,
    description: str,
    permissions: list[str],
    findings: list[dict],
) -> AIAnalysis:
    """
    Simulates an AI response without calling an external API.
    Useful for local development and automated tests.
    """

    critical_findings = [
        finding
        for finding in findings
        if finding.get("severity") == "CRITICAL"
    ]

    high_findings = [
        finding
        for finding in findings
        if finding.get("severity") == "HIGH"
    ]

    if critical_findings:
        risk_assessment = "CRITICAL"
    elif high_findings:
        risk_assessment = "HIGH"
    elif findings:
        risk_assessment = "MEDIUM"
    else:
        risk_assessment = "LOW"

    return AIAnalysis(
        summary=f"Mock security analysis for tool '{name}'.",
        risk_assessment=risk_assessment,
        confidence=1.0,
        concerns=[
            finding.get("title", finding.get("id", "Security finding"))
            for finding in findings
        ],
        recommendations=[
            "Review the detected security findings before enabling this tool."
        ] if findings else [],
    )


def analyze_tool_with_ai(
    name: str,
    description: str,
    permissions: list[str],
    findings: list[dict],
) -> AIAnalysis:

    provider = os.getenv("AI_PROVIDER", "mock").lower()

    if provider not in {"mock", "openai"}:
        raise ValueError(
        f"AI_PROVIDER inválido: '{provider}'. "
        "Use 'mock' ou 'openai'."
    )

    if provider == "mock":
        
        return analyze_tool_with_mock(
            name=name,
            description=description,
            permissions=permissions,
            findings=findings,
        )

    api_key = os.getenv("OPENAI_API_KEY")

    if not api_key:
        raise ValueError("OPENAI_API_KEY não configurada.")

    client = OpenAI(api_key=api_key)

    prompt = f"""
Tool name:
{name}

Tool description:
{description}

Tool permissions:
{permissions}

Deterministic security findings:
{findings}
"""

    response = client.responses.parse(
        model="gpt-5.6-luna",
        input=[
            {
                "role": "system",
                "content": SYSTEM_PROMPT,
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
        text_format=AIAnalysis,
    )

    if response.output_parsed is None:
        raise ValueError(
            "A IA não retornou uma análise estruturada."
        )

    return response.output_parsed