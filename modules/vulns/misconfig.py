"""
HexHunter -- Misconfiguration Detection Module.

CORS, security headers, and information disclosure checks.
"""

import re
from urllib.parse import urlparse

from utils.logger import HexHunterLogger
from utils.network import AsyncHTTPClient

logger = HexHunterLogger.get_logger("vulns.misconfig")

# Required security headers
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "medium",
        "description": "HSTS header is missing. The site does not enforce HTTPS via HSTS.",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "description": "X-Content-Type-Options header is missing. Browser MIME-sniffing is not prevented.",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": "X-Frame-Options header is missing. The page may be vulnerable to clickjacking.",
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "description": "Content-Security-Policy header is missing. No CSP policy is enforced.",
    },
    "X-XSS-Protection": {
        "severity": "low",
        "description": "X-XSS-Protection header is missing.",
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "Referrer-Policy header is missing. The browser may leak referrer information.",
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": "Permissions-Policy header is missing.",
    },
}

# Information disclosure headers
INFO_DISCLOSURE_HEADERS = [
    "X-Powered-By", "Server", "X-AspNet-Version",
    "X-AspNetMvc-Version", "X-Debug-Token", "X-Debug-Token-Link",
]


class MisconfigDetector:
    """
    Detect security misconfigurations.

    Checks:
        - CORS misconfiguration (wildcard, reflected origin)
        - Missing security headers
        - Information disclosure via headers
        - Sensitive endpoints exposed
    """

    def __init__(self, http_client: AsyncHTTPClient):
        self.http = http_client

    async def detect(self, url: str) -> list[dict]:
        """Run all misconfiguration checks against a URL."""
        findings = []

        # Get baseline response
        resp = await self.http.get(url)
        if resp.error:
            return findings

        # CORS checks
        cors_findings = await self._check_cors(url)
        findings.extend(cors_findings)

        # Security header checks
        header_findings = self._check_security_headers(url, resp.headers)
        findings.extend(header_findings)

        # Information disclosure
        info_findings = self._check_info_disclosure(url, resp.headers)
        findings.extend(info_findings)

        return findings

    async def _check_cors(self, url: str) -> list[dict]:
        """Test for CORS misconfiguration."""
        findings = []
        evil_origin = "https://evil.hexhunter.test"

        # Test with evil origin
        resp = await self.http.get(url, headers={"Origin": evil_origin})
        if resp.error:
            return findings

        acao = resp.headers.get("Access-Control-Allow-Origin",
                                resp.headers.get("access-control-allow-origin", ""))
        acac = resp.headers.get("Access-Control-Allow-Credentials",
                                resp.headers.get("access-control-allow-credentials", ""))

        if not acao:
            return findings

        # Critical: reflects arbitrary origin with credentials
        if acao == evil_origin and acac.lower() == "true":
            findings.append({
                "type": "CORS Misconfiguration",
                "severity": "critical",
                "title": "CORS reflects arbitrary origin with credentials",
                "description": (
                    "The server reflects the Origin header in Access-Control-Allow-Origin "
                    "and allows credentials. An attacker can read authenticated responses "
                    "cross-origin."
                ),
                "evidence": f"ACAO: {acao}\nACAC: {acac}",
                "request": f"GET {url}\nOrigin: {evil_origin}",
                "response": f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                "confidence": "high",
            })
            logger.finding("critical", "CORS", url, "Reflects origin with credentials")

        # High: wildcard with public access
        elif acao == "*":
            findings.append({
                "type": "CORS Misconfiguration",
                "severity": "low",
                "title": "CORS allows wildcard origin",
                "description": "Access-Control-Allow-Origin is set to '*'. This allows any origin to read responses.",
                "evidence": f"ACAO: {acao}",
                "request": url,
                "confidence": "high",
            })

        # Medium: reflects origin without credentials
        elif acao == evil_origin:
            findings.append({
                "type": "CORS Misconfiguration",
                "severity": "medium",
                "title": "CORS reflects arbitrary origin",
                "description": (
                    "The server reflects the Origin header in Access-Control-Allow-Origin "
                    "without credentials. Potential for data theft if sensitive data is "
                    "returned in public endpoints."
                ),
                "evidence": f"ACAO: {acao}",
                "request": f"GET {url}\nOrigin: {evil_origin}",
                "confidence": "high",
            })

        # Test null origin
        null_resp = await self.http.get(url, headers={"Origin": "null"})
        null_acao = null_resp.headers.get("Access-Control-Allow-Origin", "")
        if null_acao == "null":
            findings.append({
                "type": "CORS Misconfiguration",
                "severity": "medium",
                "title": "CORS allows null origin",
                "description": "The server allows 'null' as a valid origin, which can be spoofed via sandboxed iframes.",
                "evidence": f"ACAO: {null_acao}",
                "request": f"GET {url}\nOrigin: null",
                "confidence": "high",
            })

        return findings

    def _check_security_headers(self, url: str, headers: dict) -> list[dict]:
        """Check for missing security headers."""
        findings = []
        # Normalize header keys to title case
        normalized = {k.title(): v for k, v in headers.items()}

        for header, info in SECURITY_HEADERS.items():
            if header not in normalized:
                findings.append({
                    "type": "Missing Security Header",
                    "severity": info["severity"],
                    "title": f"Missing {header} header",
                    "description": info["description"],
                    "evidence": f"Header '{header}' not found in response",
                    "request": url,
                    "confidence": "high",
                })

        return findings

    def _check_info_disclosure(self, url: str, headers: dict) -> list[dict]:
        """Check for information disclosure via response headers."""
        findings = []
        normalized = {k.title(): v for k, v in headers.items()}

        for header in INFO_DISCLOSURE_HEADERS:
            if header in normalized:
                value = normalized[header]
                findings.append({
                    "type": "Information Disclosure",
                    "severity": "info",
                    "title": f"Server reveals {header}: {value}",
                    "description": f"The {header} header reveals technology information: {value}",
                    "evidence": f"{header}: {value}",
                    "request": url,
                    "confidence": "high",
                })

        return findings
