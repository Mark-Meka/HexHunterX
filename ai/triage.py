"""
HexHunterX -- AI False Positive Triage.
# AI-ENHANCED

Takes findings and evaluates them using LLM to filter false positives.
"""

import json
from ai.client import ask_ai_async
from utils.logger import HexHunterXLogger

logger = HexHunterXLogger.get_logger("ai.triage")

SYSTEM_PROMPT = """You are a senior offensive security engineer and vulnerability researcher.
Your job is to analyze potential vulnerabilities found by an automated scanner and determine if they are TRUE POSITIVE or FALSE POSITIVE.
You must output ONLY valid JSON in this exact format, with no markdown formatting or extra text:
{
    "verdict": "TRUE_POSITIVE" or "FALSE_POSITIVE",
    "confidence": "HIGH", "MEDIUM", or "LOW",
    "reasoning": "One sentence explaining why.",
    "recommendation": "What a human tester should verify next."
}
Be critical. Automated scanners often report false positives. If it looks like a generic error, WAF block, coincidental reflection, or non-exploitable context, mark it FALSE_POSITIVE.
"""

async def triage_finding(vuln_type: str, payload: str, raw_request: str, raw_response: str) -> dict:
    """Send finding to AI for triage."""
    prompt = f"""
VULNERABILITY TYPE: {vuln_type}
PAYLOAD USED: {payload}

--- RAW REQUEST ---
{raw_request}

--- RAW RESPONSE SNIPPET ---
{raw_response[:2000]}
"""
    result = {
        "verdict": "UNKNOWN",
        "confidence": "LOW",
        "reasoning": "AI triage failed or disabled.",
        "recommendation": "Manual verification required."
    }

    response_text = await ask_ai_async(prompt, SYSTEM_PROMPT)
    if not response_text:
        return result

    try:
        # Strip markdown if present
        cleaned = response_text.strip()
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        
        data = json.loads(cleaned)
        result["verdict"] = data.get("verdict", "UNKNOWN")
        result["confidence"] = data.get("confidence", "LOW")
        result["reasoning"] = data.get("reasoning", "AI parsing error")
        result["recommendation"] = data.get("recommendation", "")
    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse AI triage response: {e}")
        result["reasoning"] = f"Failed to parse JSON from AI: {response_text[:100]}"
        
    return result
