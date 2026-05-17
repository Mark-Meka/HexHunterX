"""
HexHunterX -- CSRF Detection Module (v2).

- Sensitive action detection (only flags forms doing sensitive things)
- Combines token absence and cookie vulnerability (SameSite)
- Informational severity for non-sensitive forms
"""

import re
from urllib.parse import urlparse

from utils.logger import HexHunterXLogger
from utils.network import AsyncHTTPClient
from modules.vulns.verification import Confidence

logger = HexHunterXLogger.get_logger("vulns.csrf")

SENSITIVE_ACTIONS = [
    r'password', r'email', r'transfer', r'pay', r'delete', r'remove',
    r'update', r'settings', r'profile', r'admin', r'upload', r'role',
    r'privilege', r'checkout', r'order', r'buy', r'purchase', r'user'
]

CSRF_TOKENS = [
    r'csrf', r'xsrf', r'token', r'authenticity_token', r'_csrf',
    r'__RequestVerificationToken', r'nonce'
]


class CSRFDetector:
    """
    Detect CSRF vulnerabilities with sensitive action verification.
    """

    def __init__(self, http_client: AsyncHTTPClient):
        self.http = http_client

    async def detect(self, url: str) -> list[dict]:
        findings = []
        resp = await self.http.get(url)
        if resp.error or not resp.body:
            return findings

        # Analyze cookies for SameSite
        cookies_vulnerable = self._are_cookies_vulnerable(resp.headers)

        forms = re.findall(r'<form[^>]*>(.*?)</form>', resp.body, re.IGNORECASE | re.DOTALL)
        for form_idx, form_html in enumerate(forms):
            form_tag = re.search(r'<form[^>]*>', resp.body.split(form_html)[0][-200:] + form_html[:50], re.IGNORECASE)
            action = "unknown"
            method = "GET"
            if form_tag:
                act_match = re.search(r'action=["\']([^"\']+)["\']', form_tag.group(0), re.IGNORECASE)
                if act_match: action = act_match.group(1)
                meth_match = re.search(r'method=["\']([^"\']+)["\']', form_tag.group(0), re.IGNORECASE)
                if meth_match: method = meth_match.group(1).upper()

            if method == "GET":
                continue

            has_token = self._has_csrf_token(form_html)
            is_sensitive = self._is_sensitive_form(action, form_html)

            if not has_token:
                if is_sensitive:
                    sev = "high" if cookies_vulnerable else "medium"
                    conf = Confidence.HIGH if cookies_vulnerable else Confidence.MEDIUM
                    findings.append({
                        "type": "CSRF",
                        "severity": sev,
                        "title": f"CSRF on sensitive form: {action[:30]}",
                        "description": (
                            f"Sensitive form lacks CSRF token. "
                            f"Cookies vulnerable (No SameSite=Strict/Lax): {cookies_vulnerable}."
                        ),
                        "evidence": f"[1] WHERE TESTED: {url} (Form Action: {action})\n[2] HOW TESTED: Parsed HTML form and analyzed cookies for SameSite configuration.\n[3] PAYLOAD USED: N/A (Static Analysis)\n[4] VERIFICATION OUTPUT: Missing CSRF token. Method: {method}. Cookies Vulnerable: {cookies_vulnerable}.",
                        "request": url,
                        "response": form_html[:500],
                        "confidence": conf,
                        "verification_method": "sensitive_form_analysis",
                    })
                else:
                    findings.append({
                        "type": "Missing CSRF Token (Info)",
                        "severity": "info",
                        "title": f"Missing CSRF token on non-sensitive form: {action[:30]}",
                        "description": "Form lacks CSRF token but does not appear to perform a sensitive action.",
                        "evidence": f"[1] WHERE TESTED: {url} (Form Action: {action})\n[2] HOW TESTED: Parsed HTML form and analyzed action keywords.\n[3] PAYLOAD USED: N/A (Static Analysis)\n[4] VERIFICATION OUTPUT: Missing CSRF token but action appears non-sensitive.",
                        "request": url,
                        "response": "",
                        "confidence": Confidence.LOW,
                        "verification_method": "form_analysis",
                    })

        return findings

    def _are_cookies_vulnerable(self, headers: dict) -> bool:
        set_cookies = headers.get("Set-Cookie", headers.get("set-cookie", ""))
        if not set_cookies:
            # If we don't know, assume vulnerable for form checking
            return True
        if isinstance(set_cookies, list):
            set_cookies = str(set_cookies)
        
        if "samesite=strict" in set_cookies.lower() or "samesite=lax" in set_cookies.lower():
            return False
        return True

    def _has_csrf_token(self, form_html: str) -> bool:
        for token in CSRF_TOKENS:
            if re.search(rf'name=["\']{token}["\']', form_html, re.IGNORECASE):
                return True
        return False

    def _is_sensitive_form(self, action: str, form_html: str) -> bool:
        if "login" in action.lower() or "search" in action.lower():
            return False
        for pattern in SENSITIVE_ACTIONS:
            if re.search(pattern, action, re.IGNORECASE) or re.search(pattern, form_html, re.IGNORECASE):
                return True
        return False
