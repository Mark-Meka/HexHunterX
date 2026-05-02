"""
HexHunterX -- AI Context-Aware Payloads.
# AI-ENHANCED

Generates highly targeted payloads based on the detected tech stack and WAF.
"""

import json
from ai.client import ask_ai_async
from utils.logger import HexHunterXLogger

logger = HexHunterXLogger.get_logger("ai.payloads")

SYSTEM_PROMPT = """You are an expert exploit developer. 
Generate exactly 10 highly optimized, evasion-focused payloads for the specified vulnerability type, tailored exactly to the provided Tech Stack and WAF.
Return ONLY a valid JSON array of strings. No markdown, no explanations.
Example: ["payload1", "payload2"]
"""

async def generate_payloads(vuln_type: str, tech_stack: list[str], waf_name: str = "") -> list[str]:
    """Ask AI for targeted payloads based on context."""
    stack_str = ", ".join(tech_stack) if tech_stack else "Unknown"
    waf_str = waf_name if waf_name else "None/Unknown"

    prompt = f"""
VULNERABILITY TYPE: {vuln_type}
TECH STACK: {stack_str}
WAF: {waf_str}
"""
    response_text = await ask_ai_async(prompt, SYSTEM_PROMPT)
    if not response_text:
        return []

    try:
        cleaned = response_text.strip()
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        payloads = json.loads(cleaned)
        if isinstance(payloads, list) and all(isinstance(p, str) for p in payloads):
            return payloads
        return []
    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse AI payloads: {e}")
        return []
