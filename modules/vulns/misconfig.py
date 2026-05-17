"""
HexHunterX -- Misconfiguration Detection Module (v2).

- Consolidates missing headers into a single finding.
- Consolidates info disclosure headers into a single finding.
- Removed CORS (handled by cors.py).
"""

from utils.logger import HexHunterXLogger
from utils.network import AsyncHTTPClient
from modules.vulns.verification import Confidence

logger = HexHunterXLogger.get_logger("vulns.misconfig")

SECURITY_HEADERS = [
    "Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options",
    "Content-Security-Policy", "X-XSS-Protection", "Referrer-Policy", "Permissions-Policy"
]

INFO_HEADERS = [
    "X-Powered-By", "Server", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Debug-Token", "X-Debug-Token-Link"
]


class MisconfigDetector:
    """Detect security misconfigurations and missing headers."""

    def __init__(self, http_client: AsyncHTTPClient, oob_client=None):
        self.http = http_client

    async def detect(self, url: str) -> list[dict]:
        findings = []
        resp = await self.http.get(url)
        if resp.error:
            return findings

        normalized = {k.title(): v for k, v in resp.headers.items()}

        missing = [h for h in SECURITY_HEADERS if h not in normalized]
        if missing:
            findings.append({
                "type": "Missing Security Headers (Info)",
                "severity": "info",
                "title": f"Missing Security Headers: {len(missing)} missing",
                "description": "The following security headers are missing: " + ", ".join(missing),
                "evidence": f"[1] WHERE TESTED: {url}\n[2] HOW TESTED: Analyzed HTTP response headers for missing standard security configurations.\n[3] PAYLOAD USED: N/A (Static Analysis)\n[4] VERIFICATION OUTPUT: Missing headers: {', '.join(missing)}",
                "request": url,
                "response": "",
                "confidence": Confidence.HIGH,
                "verification_method": "header_analysis",
            })

        disclosed = {h: normalized[h] for h in INFO_HEADERS if h in normalized}
        if disclosed:
            ev = "\n".join([f"{k}: {v}" for k, v in disclosed.items()])
            findings.append({
                "type": "Information Disclosure (Info)",
                "severity": "info",
                "title": "Information Disclosure via Headers",
                "description": "The server leaks version/technology info in headers.",
                "evidence": f"[1] WHERE TESTED: {url}\n[2] HOW TESTED: Analyzed HTTP response headers for technology fingerprinting leaks.\n[3] PAYLOAD USED: N/A (Static Analysis)\n[4] VERIFICATION OUTPUT:\n{ev}",
                "request": url,
                "response": "",
                "confidence": Confidence.HIGH,
                "verification_method": "header_analysis",
            })

        return findings
