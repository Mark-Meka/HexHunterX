"""
HexHunterX -- CORS Detection Module (v2).

- Validates actual credential access
- Retry verification for reflected origin
"""

from utils.logger import HexHunterXLogger
from utils.network import AsyncHTTPClient
from modules.vulns.verification import Confidence

logger = HexHunterXLogger.get_logger("vulns.cors")

class CORSDetector:
    """Detect CORS misconfigurations."""

    def __init__(self, http_client: AsyncHTTPClient):
        self.http = http_client

    async def detect(self, url: str) -> list[dict]:
        findings = []
        evil_origin = "https://evil.HexHunterX.test"

        resp = await self.http.get(url, headers={"Origin": evil_origin})
        if resp.error:
            return findings

        acao = resp.headers.get("Access-Control-Allow-Origin", resp.headers.get("access-control-allow-origin", ""))
        acac = resp.headers.get("Access-Control-Allow-Credentials", resp.headers.get("access-control-allow-credentials", ""))

        if not acao:
            return findings

        if acao == evil_origin and acac.lower() == "true":
            # Retry to confirm reflection
            resp2 = await self.http.get(url, headers={"Origin": "https://test.HexHunterX.test"})
            acao2 = resp2.headers.get("Access-Control-Allow-Origin", "")
            if acao2 == "https://test.HexHunterX.test":
                findings.append({
                    "type": "CORS Misconfiguration",
                    "severity": "critical",
                    "title": "CORS reflects arbitrary origin with credentials",
                    "description": "Server reflects Origin header and allows credentials. Enables cross-origin data theft.",
                    "evidence": f"[1] WHERE TESTED: {url}\n[2] HOW TESTED: Injected malicious Origin header to check for reflection and credential access.\n[3] PAYLOAD USED: Origin: {evil_origin}\n[4] VERIFICATION OUTPUT: Access-Control-Allow-Origin: {acao} | Access-Control-Allow-Credentials: {acac}",
                    "request": f"GET {url}\nOrigin: {evil_origin}",
                    "response": f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                    "confidence": Confidence.CONFIRMED,
                    "verification_method": "cors_reflection_retry",
                })
        elif acao == "*":
            findings.append({
                "type": "CORS Misconfiguration (Info)",
                "severity": "info",
                "title": "CORS allows wildcard origin",
                "description": "ACAO is '*'. This is informational unless sensitive data is returned.",
                "evidence": f"[1] WHERE TESTED: {url}\n[2] HOW TESTED: Sent basic request to observe default CORS headers.\n[3] PAYLOAD USED: N/A\n[4] VERIFICATION OUTPUT: Access-Control-Allow-Origin: {acao}",
                "request": url,
                "response": "",
                "confidence": Confidence.HIGH,
                "verification_method": "header_analysis",
            })
        elif acao == evil_origin:
             findings.append({
                "type": "CORS Misconfiguration",
                "severity": "medium",
                "title": "CORS reflects arbitrary origin (No Credentials)",
                "description": "Server reflects Origin header but without credentials.",
                "evidence": f"[1] WHERE TESTED: {url}\n[2] HOW TESTED: Injected malicious Origin header to check for reflection.\n[3] PAYLOAD USED: Origin: {evil_origin}\n[4] VERIFICATION OUTPUT: Access-Control-Allow-Origin: {acao}",
                "request": f"GET {url}\nOrigin: {evil_origin}",
                "response": "",
                "confidence": Confidence.HIGH,
                "verification_method": "header_analysis",
            })

        return findings
