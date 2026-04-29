"""
HexHunter -- Open Redirect Detection Module.

Detect open redirect vulnerabilities via parameter injection.
"""

from urllib.parse import urlencode, urlparse, parse_qs

from utils.logger import HexHunterLogger
from utils.network import AsyncHTTPClient
from modules.fuzzing.payloads import PayloadEngine

logger = HexHunterLogger.get_logger("vulns.redirect")

# Common parameter names used for redirects
REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri", "return", "return_url",
    "next", "next_url", "goto", "target", "dest", "destination",
    "rurl", "redir", "out", "view", "link", "ref", "continue",
]


class OpenRedirectDetector:
    """
    Detect open redirect vulnerabilities.

    Methodology:
        1. Identify redirect parameters (from URL or common names)
        2. Inject external domain payloads
        3. Check if response redirects to external domain
        4. Validate via redirect chain analysis
    """

    EVIL_DOMAIN = "evil.hexhunter.test"

    def __init__(self, http_client: AsyncHTTPClient):
        self.http = http_client

    async def detect(self, url: str) -> list[dict]:
        """Test URL for open redirect vulnerabilities."""
        findings = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        existing_params = parse_qs(parsed.query)

        # Determine which params to test
        test_params = list(existing_params.keys())
        if not test_params:
            test_params = REDIRECT_PARAMS

        for param in test_params:
            for payload in self._get_payloads():
                test_url = f"{base}?{urlencode({param: payload})}"

                # Don't follow redirects -- we want to inspect the redirect
                resp = await self.http.get(test_url, follow_redirects=False)

                if resp.error:
                    continue

                # Check for redirect status codes
                if resp.status_code in {301, 302, 303, 307, 308}:
                    location = resp.headers.get("Location", resp.headers.get("location", ""))

                    if self._is_external_redirect(location):
                        poc = PayloadEngine.generate_poc("redirect", base, param, payload)
                        finding = {
                            "type": "Open Redirect",
                            "severity": "medium",
                            "title": f"Open Redirect via parameter '{param}'",
                            "description": (
                                f"The parameter '{param}' accepts arbitrary redirect URLs. "
                                f"The server responded with HTTP {resp.status_code} redirecting "
                                f"to: {location}"
                            ),
                            "evidence": f"Redirect: {resp.status_code} → {location}\nPayload: {payload}",
                            "request": test_url,
                            "response": f"HTTP {resp.status_code}\nLocation: {location}",
                            "reproduction": poc,
                            "confidence": "high",
                        }
                        findings.append(finding)
                        logger.finding("medium", "Open Redirect", base, f"param={param}")
                        break

                # Also check for meta refresh and JS redirects in body
                if resp.status_code == 200:
                    if self._check_body_redirect(resp.body, payload):
                        finding = {
                            "type": "Open Redirect (Client-side)",
                            "severity": "low",
                            "title": f"Client-side redirect via parameter '{param}'",
                            "description": (
                                f"The parameter '{param}' causes a client-side redirect "
                                f"via meta refresh or JavaScript."
                            ),
                            "evidence": f"Payload: {payload}",
                            "request": test_url,
                            "response": resp.body[:1000],
                            "confidence": "medium",
                        }
                        findings.append(finding)
                        break

        return findings

    def _get_payloads(self) -> list[str]:
        """Generate redirect payloads with the test domain."""
        return [
            f"https://{self.EVIL_DOMAIN}",
            f"//{self.EVIL_DOMAIN}",
            f"/\\{self.EVIL_DOMAIN}",
            f"https://{self.EVIL_DOMAIN}/path",
            f"/{self.EVIL_DOMAIN}",
            f"///{self.EVIL_DOMAIN}",
        ]

    def _is_external_redirect(self, location: str) -> bool:
        """Check if a Location header points to an external domain."""
        if not location:
            return False
        if self.EVIL_DOMAIN in location:
            return True
        try:
            parsed = urlparse(location)
            if parsed.hostname and parsed.hostname != self.EVIL_DOMAIN:
                # Generic external redirect detection
                return parsed.scheme in ("http", "https") and parsed.hostname
        except Exception:
            pass
        return False

    @staticmethod
    def _check_body_redirect(body: str, payload: str) -> bool:
        """Check for client-side redirects in response body."""
        import re
        patterns = [
            r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\'].*?' + re.escape(payload),
            r'window\.location\s*=\s*["\']' + re.escape(payload),
            r'location\.href\s*=\s*["\']' + re.escape(payload),
        ]
        for pattern in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                return True
        return False
