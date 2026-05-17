"""
HexHunterX -- AI Client.
# AI-ENHANCED

Multi-provider wrapper supporting:
  - Google AI Studio  (provider: "google")
  - OpenRouter        (provider: "openrouter")

Configure via config/default.yaml:
    ai:
      provider: "google"          # or "openrouter"
      api_key:  "<your-api-key>"
      model:    "gemma-4-26b-a4b-it"  # Reverted due to 500 Internal Server Error on 31b
      enabled:  true
"""

import json
import httpx
import requests
from utils.logger import HexHunterXLogger

logger = HexHunterXLogger.get_logger("ai.client")

# ── Provider Endpoints ────────────────────────────────────────────────────────
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_REFERER = "https://github.com/Mark-Meka/HexHunterX"

GOOGLE_AI_URL_TEMPLATE = (
    "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
)

# ── Module State ──────────────────────────────────────────────────────────────
_api_key  = "AIzaSyA2y9ulI18v5ANOe6aqnQVhcbAhD65lSaw"
_model    = "gemma-4-26b-a4b-it"
_provider = "google"   # "google" | "openrouter"


def set_api_key(key: str):
    global _api_key
    _api_key = key or ""


def set_model(model: str):
    global _model
    if model:
        _model = model


def set_provider(provider: str):
    global _provider
    if provider in ("google", "openrouter"):
        _provider = provider
    else:
        logger.warning(f"Unknown AI provider '{provider}', falling back to 'google'")


def has_api_key() -> bool:
    return bool(_api_key)


# ── Google AI Studio ──────────────────────────────────────────────────────────
def _google_url() -> str:
    return GOOGLE_AI_URL_TEMPLATE.format(model=_model)


def _google_payload(prompt: str, system: str) -> dict:
    payload = {"contents": [{"role": "user", "parts": [{"text": prompt}]}]}
    if system:
        payload["systemInstruction"] = {"role": "user", "parts": [{"text": system}]}
    return payload


def _google_headers() -> dict:
    return {"Content-Type": "application/json"}


def _google_parse(response_json: dict) -> str:
    try:
        return response_json["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError):
        logger.warning(f"Unexpected Google AI response structure: {str(response_json)[:200]}")
        return ""


# ── OpenRouter ────────────────────────────────────────────────────────────────
def _openrouter_payload(prompt: str, system: str) -> dict:
    return {
        "model": _model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": prompt},
        ],
    }


def _openrouter_headers() -> dict:
    return {
        "Authorization": f"Bearer {_api_key}",
        "HTTP-Referer":  OPENROUTER_REFERER,
        "Content-Type":  "application/json",
    }


def _openrouter_parse(response_json: dict) -> str:
    try:
        return response_json["choices"][0]["message"]["content"]
    except (KeyError, IndexError):
        logger.warning(f"Unexpected OpenRouter response structure: {str(response_json)[:200]}")
        return ""


# ── Sync API Call ─────────────────────────────────────────────────────────────
def ask_ai(prompt: str, system: str = "") -> str:
    """Synchronous call to the configured AI provider."""
    if not has_api_key():
        logger.warning("AI features enabled but api_key is not set in config/default.yaml.")
        return ""

    try:
        if _provider == "google":
            url     = _google_url() + f"?key={_api_key}"
            headers = _google_headers()
            payload = _google_payload(prompt, system)
            resp    = requests.post(url, headers=headers, json=payload, timeout=60)
            resp.raise_for_status()
            return _google_parse(resp.json())
        else:
            resp = requests.post(
                OPENROUTER_URL,
                headers=_openrouter_headers(),
                json=_openrouter_payload(prompt, system),
                timeout=60,
            )
            resp.raise_for_status()
            return _openrouter_parse(resp.json())

    except requests.exceptions.HTTPError as e:
        logger.warning(f"AI API call failed: HTTP {e.response.status_code} - {e.response.text}")
        return ""
    except requests.exceptions.Timeout:
        logger.warning("AI API call failed: Connection timed out after 60 seconds.")
        return ""
    except Exception as e:
        logger.warning(f"AI API call failed: {type(e).__name__} - {e}")
        return ""


# ── Async API Call ────────────────────────────────────────────────────────────
async def ask_ai_async(prompt: str, system: str = "") -> str:
    """Asynchronous call to the configured AI provider."""
    if not has_api_key():
        logger.warning("AI features enabled but api_key is not set in config/default.yaml.")
        return ""

    try:
        async with httpx.AsyncClient(timeout=60) as client:
            if _provider == "google":
                url     = _google_url() + f"?key={_api_key}"
                headers = _google_headers()
                payload = _google_payload(prompt, system)
                resp    = await client.post(url, headers=headers, json=payload)
            else:
                resp    = await client.post(
                    OPENROUTER_URL,
                    headers=_openrouter_headers(),
                    json=_openrouter_payload(prompt, system),
                )

            resp.raise_for_status()
            data = resp.json()
            return _google_parse(data) if _provider == "google" else _openrouter_parse(data)

    except httpx.HTTPStatusError as e:
        logger.warning(f"Async AI API call failed: HTTP {e.response.status_code} - {e.response.text}")
        return ""
    except httpx.TimeoutException:
        logger.warning("Async AI API call failed: Connection timed out after 60 seconds.")
        return ""
    except Exception as e:
        logger.warning(f"Async AI API call failed: {type(e).__name__} - {e}")
        return ""
