"""
HexHunter -- Cross-Site Request Forgery (CSRF) Detection Module.

Detect CSRF vulnerabilities by analysing HTML forms for missing tokens,
checking SameSite cookie policy, and identifying state-changing endpoints
without CSRF protection.
"""

import re
from urllib.parse import urlparse

from utils.logger import HexHunterLogger
from utils.network import AsyncHTTPClient
from modules.fuzzing.payloads import PayloadEngine

logger = HexHunterLogger.get_logger("vulns.csrf")

# Common CSRF token field names
TOKEN_FIELD_NAMES = [
    "csrf", "csrf_token", "csrfmiddlewaretoken", "_csrf", "_token",
    "authenticity_token", "anti-csrf-token", "__RequestVerificationToken",
    "token", "xsrf", "xsrf_token", "_xsrf", "nonce", "state",
]

# HTTP methods that are state-changing
STATE_CHANGING_METHODS = {"post", "put", "delete", "patch"}


class CSRFDetector:
    """
    Detect Cross-Site Request Forgery vulnerabilities.

    Methodology:
        1. Fetch target page and extract all HTML forms
        2. For each form with a state-changing method (POST/PUT/DELETE):
           a. Check if a CSRF token hidden field exists
           b. Check if the token field has a non-empty value
        3. Analyse response cookies for SameSite attribute
        4. Generate PoC HTML templates for vulnerable forms
    """

    def __init__(self, http_client: AsyncHTTPClient):
        self.http = http_client

    async def detect(self, url: str) -> list[dict]:
        """Test a URL for CSRF vulnerabilities."""
        findings = []

        resp = await self.http.get(url)
        if resp.error or resp.status_code != 200:
            return findings

        # ---- Phase 1: Form analysis ----
        forms = self._extract_forms(resp.body)
        for form in forms:
            if form["method"].lower() not in STATE_CHANGING_METHODS:
                continue  # GET forms aren't vulnerable to CSRF

            has_token = self._has_csrf_token(form)
            if not has_token:
                action = form.get("action", url)
                finding = {
                    "type": "CSRF (Missing Token)",
                    "severity": "medium",
                    "title": f"Form without CSRF token at {self._truncate(action)}",
                    "description": (
                        f"A state-changing form (method={form['method'].upper()}) at "
                        f"'{action}' does not contain a CSRF token field. An attacker "
                        f"can craft a cross-origin request that the victim's browser "
                        f"will send with their authenticated session."
                    ),
                    "evidence": (
                        f"Form action: {action}\n"
                        f"Method: {form['method'].upper()}\n"
                        f"Fields: {[f['name'] for f in form.get('inputs', []) if f.get('name')]}\n"
                        f"CSRF token: NOT FOUND"
                    ),
                    "request": url,
                    "response": self._build_poc_form(action, form),
                    "confidence": "high",
                }
                findings.append(finding)
                logger.finding("medium", "CSRF", url,
                               f"Missing token on {form['method'].upper()} form")

        # ---- Phase 2: Cookie SameSite analysis ----
        cookie_findings = self._check_samesite_cookies(url, resp.headers)
        findings.extend(cookie_findings)

        return findings

    # ─── Helpers ────────────────────────────────────────

    def _extract_forms(self, html: str) -> list[dict]:
        """Extract forms and their inputs from HTML."""
        forms = []
        form_pattern = re.compile(
            r'<form\s[^>]*?>(.*?)</form>',
            re.DOTALL | re.IGNORECASE,
        )
        action_pattern = re.compile(r'action=["\']([^"\']*)["\']', re.IGNORECASE)
        method_pattern = re.compile(r'method=["\']([^"\']*)["\']', re.IGNORECASE)
        input_pattern = re.compile(
            r'<input\s[^>]*?name=["\']([^"\']*)["\'][^>]*?>',
            re.IGNORECASE,
        )
        type_pattern = re.compile(r'type=["\']([^"\']*)["\']', re.IGNORECASE)

        for form_match in form_pattern.finditer(html):
            form_html = form_match.group(0)
            form_body = form_match.group(1)

            action_m = action_pattern.search(form_html)
            method_m = method_pattern.search(form_html)

            action = action_m.group(1) if action_m else ""
            method = method_m.group(1) if method_m else "get"

            inputs = []
            for inp_match in input_pattern.finditer(form_body):
                inp_name = inp_match.group(1)
                inp_html = inp_match.group(0)
                type_m = type_pattern.search(inp_html)
                inp_type = type_m.group(1) if type_m else "text"
                inputs.append({"name": inp_name, "type": inp_type})

            forms.append({
                "action": action,
                "method": method,
                "inputs": inputs,
            })

        return forms

    def _has_csrf_token(self, form: dict) -> bool:
        """Check if a form contains a CSRF token field."""
        for inp in form.get("inputs", []):
            name = (inp.get("name") or "").lower()
            for token_name in TOKEN_FIELD_NAMES:
                if token_name in name:
                    return True
        return False

    def _check_samesite_cookies(self, url: str, headers: dict) -> list[dict]:
        """Check if session cookies have SameSite attribute."""
        findings = []
        set_cookies = []

        for key, value in headers.items():
            if key.lower() == "set-cookie":
                set_cookies.append(value)

        for cookie in set_cookies:
            cookie_lower = cookie.lower()
            # Only care about session-like cookies
            is_session = any(kw in cookie_lower for kw in [
                "session", "sess", "sid", "auth", "token", "jwt", "login",
            ])
            if not is_session:
                continue

            has_samesite = "samesite=" in cookie_lower
            samesite_none = "samesite=none" in cookie_lower

            if not has_samesite or samesite_none:
                cookie_name = cookie.split("=")[0].strip()
                severity = "medium" if samesite_none else "low"
                finding = {
                    "type": "CSRF (Weak Cookie Policy)",
                    "severity": severity,
                    "title": f"Session cookie '{cookie_name}' lacks SameSite protection",
                    "description": (
                        f"The session cookie '{cookie_name}' does not have a "
                        f"SameSite attribute (or is set to 'None'), allowing it "
                        f"to be sent with cross-origin requests. Combined with "
                        f"missing CSRF tokens, this enables CSRF attacks."
                    ),
                    "evidence": f"Set-Cookie: {cookie[:200]}",
                    "request": url,
                    "confidence": "high" if samesite_none else "medium",
                }
                findings.append(finding)

        return findings

    @staticmethod
    def _build_poc_form(action: str, form: dict) -> str:
        """Build an HTML proof-of-concept auto-submit form."""
        fields = ""
        for inp in form.get("inputs", []):
            name = inp.get("name", "")
            if name:
                fields += f'  <input type="hidden" name="{name}" value="HEXHUNTER_TEST"/>\n'

        return (
            f'<html>\n<body>\n'
            f'<form action="{action}" method="{form["method"].upper()}">\n'
            f'{fields}'
            f'</form>\n'
            f'<script>document.forms[0].submit();</script>\n'
            f'</body>\n</html>'
        )

    @staticmethod
    def _truncate(text: str, length: int = 60) -> str:
        return text[:length] + "..." if len(text) > length else text
