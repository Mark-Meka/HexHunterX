"""
HexHunterX -- AI Client.
# AI-ENHANCED

Wrapper around OpenRouter API for Claude-3.5-Sonnet integration.
"""

import os
import json
import httpx
import requests
from utils.logger import HexHunterXLogger

logger = HexHunterXLogger.get_logger("ai.client")

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
MODEL = "anthropic/claude-sonnet-4-5"
REFERER = "https://github.com/Mark-Meka/HexHunterX"

_api_key = os.environ.get("OPENROUTER_API_KEY", "")

def set_api_key(key: str):
    global _api_key
    _api_key = key

def has_api_key() -> bool:
    return bool(_api_key)

def _build_headers():
    return {
        "Authorization": f"Bearer {_api_key}",
        "HTTP-Referer": REFERER,
        "Content-Type": "application/json"
    }

def _build_payload(prompt: str, system: str):
    return {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt}
        ]
    }

def ask_ai(prompt: str, system: str = "") -> str:
    """Sync request to OpenRouter."""
    if not has_api_key():
        logger.warning("AI features enabled but OPENROUTER_API_KEY not set.")
        return ""
        
    try:
        response = requests.post(
            OPENROUTER_URL,
            headers=_build_headers(),
            json=_build_payload(prompt, system),
            timeout=30
        )
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]
    except Exception as e:
        logger.warning(f"AI API call failed: {e}")
        return ""

async def ask_ai_async(prompt: str, system: str = "") -> str:
    """Async request to OpenRouter."""
    if not has_api_key():
        logger.warning("AI features enabled but OPENROUTER_API_KEY not set.")
        return ""

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                OPENROUTER_URL,
                headers=_build_headers(),
                json=_build_payload(prompt, system)
            )
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]
    except Exception as e:
        logger.warning(f"Async AI API call failed: {e}")
        return ""
