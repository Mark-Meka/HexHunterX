"""
HexHunterX -- CORS Misconfiguration Detection Module.

Deep CORS testing using the full payload library -- reflected origin,
null origin, subdomain suffix/prefix matching, and credential theft PoC.
"""

from urllib.parse import urlparse

from utils.logger import HexHunterXLogger
from utils.network import AsyncHTTPClient
from modules.fuzzing.payloads import PayloadEngine

logger = HexHunterXLogger.get_logger("vulns.cors")

# Additional origin test cases generated from the target domain
ORIGIN_TEMPLATES = [
    "https://evil.HexHunterX.test",
    "null",
    # Subdomain suffix match -- TARGET.com.evil.com
    "https://{domain}.evil.HexHunterX.test",
    # Prefix match -- evilTARGET.com
    "https://evil{domain}",
    # Null byte
    "https://{domain}%00.evil.HexHunterX.test",
    # Backtick
    "https://{domain}%60.evil.HexHunterX.test",
    # With credentials separator
    "https://evil.HexHunterX.test%40{domain}",
]


class CORSDetector:
    """
    Detect CORS misconfiguration vulnerabilities.

    Methodology:
        1. Send requests with various malicious Origin headers
        2. Analyse Access-Control-Allow-Origin (ACAO) responses
        3. Check if credentials are allowed (ACAC: true)
        4. Test null origin via sandboxed iframes
        5. Generate exploitation PoC scripts
    """

    def __init__(self, http_client: AsyncHTTPClient):
        self.http = http_client

    async def detect(self, url: str) -> list[dict]:
        """Test a URL for CORS misconfiguration."""
        findings = []
        parsed = urlparse(url)
        target_domain = parsed.hostname or ""

        # Build the list of origins to test
        origins = self._build_origins(target_domain)

        for origin in origins:
            resp = await self.http.get(url, headers={"Origin": origin})
            if resp.error:
                continue

            acao = self._get_header(resp.headers, "Access-Control-Allow-Origin")
            acac = self._get_header(resp.headers, "Access-Control-Allow-Credentials")

            if not acao:
                continue  # No ACAO header = not configured

            # ---- Critical: reflected attacker origin + credentials ----
            if acao == origin and acac.lower() == "true" and origin != "null":
                poc = PayloadEngine.generate_poc("cors", url, "Origin header", origin)
                finding = {
                    "type": "CORS Misconfiguration",
                    "severity": "critical",
                    "title": "CORS reflects arbitrary origin with credentials",
                    "description": (
                        f"The server reflected the Origin '{origin}' in the "
                        f"Access-Control-Allow-Origin header AND allows credentials. "
                        f"An attacker can steal authenticated data cross-origin."
                    ),
                    "evidence": (
                        f"Origin: {origin}\n"
                        f"ACAO: {acao}\n"
                        f"ACAC: {acac}"
                    ),
                    "request": f"GET {url}\nOrigin: {origin}",
                    "response": (
                        f"Access-Control-Allow-Origin: {acao}\n"
                        f"Access-Control-Allow-Credentials: {acac}"
                    ),
                    "reproduction": poc,
                    "confidence": "high",
                }
                findings.append(finding)
                logger.finding("critical", "CORS", url,
                               f"Reflects origin '{origin}' + credentials")
                break  # Critical found, stop testing

            # ---- High: wildcard origin ----
            if acao == "*":
                finding = {
                    "type": "CORS Misconfiguration",
                    "severity": "low",
                    "title": "CORS allows wildcard origin",
                    "description": (
                        "Access-Control-Allow-Origin is set to '*'. "
                        "Any origin can read responses from this endpoint."
                    ),
                    "evidence": f"ACAO: {acao}",
                    "request": f"GET {url}\nOrigin: {origin}",
                    "response": f"Access-Control-Allow-Origin: {acao}",
                    "confidence": "high",
                }
                findings.append(finding)
                # Continue testing -- might also have credential issues

            # ---- Medium: reflected origin without credentials ----
            if acao == origin and acac.lower() != "true" and origin != "null":
                finding = {
                    "type": "CORS Misconfiguration",
                    "severity": "medium",
                    "title": f"CORS reflects origin '{self._truncate(origin)}'",
                    "description": (
                        f"The server reflected the Origin '{origin}' in ACAO "
                        f"without credentials. Sensitive data on public endpoints "
                        f"may be readable cross-origin."
                    ),
                    "evidence": f"Origin: {origin}\nACAO: {acao}",
                    "request": f"GET {url}\nOrigin: {origin}",
                    "response": f"Access-Control-Allow-Origin: {acao}",
                    "confidence": "high",
                }
                findings.append(finding)

            # ---- Medium: null origin allowed ----
            if origin == "null" and acao == "null":
                finding = {
                    "type": "CORS Misconfiguration",
                    "severity": "medium",
                    "title": "CORS allows null origin",
                    "description": (
                        "The server allows 'null' as a valid origin. "
                        "An attacker can spoof the null origin using sandboxed iframes."
                    ),
                    "evidence": f"ACAO: {acao}",
                    "request": f"GET {url}\nOrigin: null",
                    "response": f"Access-Control-Allow-Origin: {acao}",
                    "confidence": "high",
                }
                findings.append(finding)

        # Deduplicate by type
        return self._dedupe(findings)

    def _build_origins(self, domain: str) -> list[str]:
        """Build origin list from templates + static payloads."""
        origins = []
        for tmpl in ORIGIN_TEMPLATES:
            origins.append(tmpl.replace("{domain}", domain))

        # Add payloads from the payload engine
        for payload in PayloadEngine.get_payloads("cors"):
            if payload.startswith("http") or payload == "null":
                origins.append(payload.replace("TARGET", f"https://{domain}"))

        return list(dict.fromkeys(origins))  # Dedupe, preserve order

    @staticmethod
    def _get_header(headers: dict, name: str) -> str:
        """Case-insensitive header lookup."""
        for k, v in headers.items():
            if k.lower() == name.lower():
                return v
        return ""

    @staticmethod
    def _truncate(text: str, length: int = 50) -> str:
        return text[:length] + "..." if len(text) > length else text

    @staticmethod
    def _dedupe(findings: list[dict]) -> list[dict]:
        """Remove duplicate findings by type."""
        seen = set()
        unique = []
        for f in findings:
            key = f["type"] + f.get("title", "")
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
