"""
HexHunterX -- AI Report Writer.
# AI-ENHANCED

Generates an executive summary and remediation priorities based on findings.
"""

import json
from ai.client import ask_ai_async
from utils.logger import HexHunterXLogger

logger = HexHunterXLogger.get_logger("ai.report_writer")

SYSTEM_PROMPT = """You are a Principal Security Consultant writing an executive report.
Based on the provided vulnerability findings, return a JSON object with:
{
    "executive_summary": "Exactly 3 sentences summarizing the overall security posture and risk.",
    "critical_attack_chain": "A realistic attack chain describing how the most critical findings could be combined.",
    "remediation_priorities": [
        {"title": "Priority 1", "reasoning": "Why do this first"},
        {"title": "Priority 2", "reasoning": "Why do this second"},
        {"title": "Priority 3", "reasoning": "Why do this third"}
    ]
}
Output ONLY valid JSON, no markdown formatting.
"""

async def generate_executive_summary(target_domain: str, findings: list[dict]) -> dict:
    """Generate an AI executive summary for the report."""
    if not findings:
        return {
            "executive_summary": f"No vulnerabilities were found on {target_domain}.",
            "critical_attack_chain": "N/A",
            "remediation_priorities": []
        }

    # Summarize findings to avoid token limits
    summary_findings = []
    for f in findings:
        summary_findings.append({
            "type": f.get("type"),
            "severity": f.get("severity"),
            "title": f.get("title")
        })

    prompt = f"""
TARGET: {target_domain}
FINDINGS:
{json.dumps(summary_findings, indent=2)}
"""

    response_text = await ask_ai_async(prompt, SYSTEM_PROMPT)
    if not response_text:
        return {}

    try:
        cleaned = response_text.strip()
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        return json.loads(cleaned)
    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse AI report summary: {e}")
        return {}
