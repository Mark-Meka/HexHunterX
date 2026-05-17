"""
HexHunterX -- AI False Positive Triage.
# AI-ENHANCED

Takes findings and evaluates them using LLM to filter false positives.
"""

import json
import re
from ai.client import ask_ai_async
from utils.logger import HexHunterXLogger

logger = HexHunterXLogger.get_logger("ai.triage")

SYSTEM_PROMPT = """You are a senior offensive security engineer and vulnerability researcher.
Analyze the provided vulnerability finding and respond ONLY with a raw JSON object.
Do NOT use markdown, bullet points, or any explanation outside the JSON object.
Your entire response must be parseable by json.loads().

Required JSON format:
{
  "verdict": "TRUE_POSITIVE",
  "confidence": "HIGH",
  "reasoning": "one sentence",
  "detailed_description": "2-3 paragraphs providing a highly detailed technical explanation of the vulnerability, how it works, and its exact impact based on the provided evidence.",
  "remediation": "1-2 paragraphs explaining exactly how to fix the vulnerability.",
  "recommendation": "one sentence"
}

verdict must be exactly "TRUE_POSITIVE" or "FALSE_POSITIVE".
confidence must be exactly "HIGH", "MEDIUM", or "LOW".

Be critical. If the response looks like a generic error, WAF block, or coincidental reflection, use FALSE_POSITIVE.
"""


def _extract_json(text: str) -> dict | None:
    """
    Try multiple strategies to extract a JSON object from the AI response.
    Handles cases where the model wraps JSON in markdown or adds extra text.
    """
    if not text:
        return None

    # Strategy 1: Direct parse
    try:
        return json.loads(text.strip())
    except json.JSONDecodeError:
        pass

    # Strategy 2: Strip ```json ... ``` markdown fences
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
        try:
            return json.loads(cleaned.strip())
        except json.JSONDecodeError:
            pass

    # Strategy 3: Find first { ... } block via regex
    match = re.search(r"\{[^{}]*\"verdict\"[^{}]*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    # Strategy 4: Infer verdict from plain-text keywords if JSON fails entirely
    text_lower = text.lower()
    if "true_positive" in text_lower or "true positive" in text_lower:
        return {
            "verdict": "TRUE_POSITIVE",
            "confidence": "MEDIUM",
            "reasoning": text[:200].replace("\n", " "),
            "detailed_description": "The AI model confirmed this is a true positive but failed to return a structured JSON response with a detailed description.",
            "remediation": "Please consult standard security guidelines for remediation.",
            "recommendation": "Manual verification recommended.",
        }
    if "false_positive" in text_lower or "false positive" in text_lower:
        return {
            "verdict": "FALSE_POSITIVE",
            "confidence": "MEDIUM",
            "reasoning": text[:200].replace("\n", " "),
            "detailed_description": "The AI model flagged this as a false positive but failed to return a structured JSON response.",
            "remediation": "N/A",
            "recommendation": "No action required.",
        }

    return None


async def triage_finding(
    vuln_type: str,
    payload: str,
    raw_request: str,
    raw_response: str,
) -> dict:
    """Send finding to AI for triage and return structured verdict."""

    prompt = f"""VULNERABILITY TYPE: {vuln_type}
PAYLOAD USED: {payload}

--- RAW REQUEST ---
{raw_request}

--- RAW RESPONSE SNIPPET ---
{raw_response[:2000]}

Respond ONLY with the JSON object. No other text."""

    result = {
        "verdict": "UNKNOWN",
        "confidence": "LOW",
        "reasoning": "AI triage failed or disabled.",
        "recommendation": "Manual verification required.",
    }

    response_text = await ask_ai_async(prompt, SYSTEM_PROMPT)
    if not response_text:
        return result

    parsed = _extract_json(response_text)
    if parsed:
        result["verdict"]        = parsed.get("verdict", "UNKNOWN")
        result["confidence"]     = parsed.get("confidence", "LOW")
        result["reasoning"]      = parsed.get("reasoning", "")
        result["recommendation"] = parsed.get("recommendation", "")
    else:
        logger.warning(f"AI triage: could not parse JSON from response: {response_text[:150]}")
        result["reasoning"] = f"Unparseable AI response: {response_text[:100]}"

    return result
