"""
HexHunterX -- Open Redirect Detection Module (v2).

Enhanced with retry verification and confidence tiers.
Only tests existing redirect-related parameters.
"""

from urllib.parse import urlencode, urlparse, parse_qs
import re

from utils.logger import HexHunterXLogger
from utils.network import AsyncHTTPClient
from modules.fuzzing.payloads import PayloadEngine
from modules.vulns.verification import Confidence

logger = HexHunterXLogger.get_logger("vulns.redirect")

REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri", "return", "return_url",
    "next", "next_url", "goto", "target", "dest", "destination",
    "rurl", "redir", "out", "view", "link", "ref", "continue",
]


class OpenRedirectDetector:
    """
    Detect open redirect vulnerabilities with verification.

    Methodology:
        1. Only test existing params whose names match redirect patterns
        2. Inject external domain payloads
        3. Verify 3xx + Location header host parsing
        4. Retry verification for confirmed findings
        5. Check meta-refresh and JS redirects in body
    """

    EVIL_DOMAIN = "evil.HexHunterX.test"

    def __init__(self, http_client: AsyncHTTPClient):
        self.http = http_client

    async def detect(self, url: str) -> list[dict]:
        findings = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        existing_params = parse_qs(parsed.query)

        test_params = [p for p in existing_params if p.lower() in REDIRECT_PARAMS]
        if not test_params:
            return findings

        for param in test_params:
            for payload in self._get_payloads():
                test_url = f"{base}?{urlencode({param: payload})}"
                resp = await self.http.get(test_url, follow_redirects=False)
                if resp.error:
                    continue

                if resp.status_code in {301, 302, 303, 307, 308}:
                    location = resp.headers.get("Location",
                                                resp.headers.get("location", ""))
                    if self._is_external_redirect(location):
                        # Retry verification
                        resp2 = await self.http.get(test_url, follow_redirects=False)
                        retry_ok = (
                            not resp2.error
                            and resp2.status_code in {301, 302, 303, 307, 308}
                            and self._is_external_redirect(
                                resp2.headers.get("Location",
                                                  resp2.headers.get("location", ""))
                            )
                        )
                        conf = Confidence.CONFIRMED if retry_ok else Confidence.HIGH
                        poc = PayloadEngine.generate_poc("redirect", base, param, payload)
                        findings.append({
                            "type": "Open Redirect",
                            "severity": "medium",
                            "title": f"Open Redirect via parameter '{param}'",
                            "description": (
                                f"Parameter '{param}' redirects to external domain. "
                                f"HTTP {resp.status_code} → {location}. "
                                f"Retry: {'confirmed' if retry_ok else 'not retried'}."
                            ),
                            "evidence": (
                                f"Status: {resp.status_code}\n"
                                f"Location: {location}\n"
                                f"Payload: {payload}\n"
                                f"Retry confirmed: {retry_ok}"
                            ),
                            "request": test_url,
                            "response": f"HTTP {resp.status_code}\nLocation: {location}",
                            "reproduction": poc,
                            "confidence": conf,
                            "verification_method": "redirect_header_analysis",
                        })
                        break

                # Check body redirects (meta refresh, JS)
                if resp.status_code == 200:
                    body_redirect = self._check_body_redirect(resp.body, payload)
                    if body_redirect:
                        findings.append({
                            "type": "Open Redirect (Client-side)",
                            "severity": "low",
                            "title": f"Client-side redirect via parameter '{param}'",
                            "description": (
                                f"Parameter '{param}' causes {body_redirect} redirect."
                            ),
                            "evidence": f"Type: {body_redirect}\nPayload: {payload}",
                            "request": test_url,
                            "response": resp.body[:1000],
                            "confidence": Confidence.MEDIUM,
                            "verification_method": "body_redirect_analysis",
                        })
                        break

        return findings

    def _get_payloads(self):
        return [
            f"https://{self.EVIL_DOMAIN}",
            f"//{self.EVIL_DOMAIN}",
            f"/\\{self.EVIL_DOMAIN}",
            f"https://{self.EVIL_DOMAIN}/path",
        ]

    def _is_external_redirect(self, location):
        if not location:
            return False
        try:
            parsed = urlparse(location)
            host = (parsed.hostname or "").lower()
            if host == self.EVIL_DOMAIN.lower():
                return True
            if location.startswith("//"):
                pr = urlparse("https:" + location)
                if (pr.hostname or "").lower() == self.EVIL_DOMAIN.lower():
                    return True
            if location.startswith("/\\"):
                bs = urlparse("https:" + location.replace("\\", "/"))
                if (bs.hostname or "").lower() == self.EVIL_DOMAIN.lower():
                    return True
        except Exception:
            pass
        return False

    def _check_body_redirect(self, body, payload):
        patterns = [
            (r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\'].*?'
             + re.escape(payload), "meta-refresh"),
            (r'window\.location\s*=\s*["\']' + re.escape(payload), "JS window.location"),
            (r'location\.href\s*=\s*["\']' + re.escape(payload), "JS location.href"),
            (r'location\.replace\s*\(\s*["\']' + re.escape(payload), "JS location.replace"),
        ]
        for pattern, name in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                return name
        return None
