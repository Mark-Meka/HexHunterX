"""
HexHunter -- XSS Detection Module.

Detect reflected XSS and basic DOM-based XSS via reflection analysis.
"""

import re
from urllib.parse import urlencode, urlparse, parse_qs, urljoin

from utils.logger import HexHunterLogger
from utils.network import AsyncHTTPClient
from modules.fuzzing.payloads import PayloadEngine

logger = HexHunterLogger.get_logger("vulns.xss")

# Context detection patterns
CONTEXT_PATTERNS = {
    "html_tag": re.compile(r"<[^>]*CANARY[^>]*>", re.IGNORECASE),
    "html_attr": re.compile(r'=["\'][^"\']*CANARY[^"\']*["\']', re.IGNORECASE),
    "script": re.compile(r"<script[^>]*>[^<]*CANARY[^<]*</script>", re.IGNORECASE),
    "comment": re.compile(r"<!--[^>]*CANARY[^>]*-->", re.IGNORECASE),
}


class XSSDetector:
    """
    Detect reflected and DOM-based XSS vulnerabilities.

    Methodology:
        1. Inject canary in all parameters
        2. Check if canary is reflected in response
        3. Determine reflection context (HTML, attribute, script, etc.)
        4. Test context-appropriate payloads
        5. Verify payload execution in response
        6. Reduce false positives via validation
    """

    CANARY = "hxhx5s"

    def __init__(self, http_client: AsyncHTTPClient):
        self.http = http_client

    async def detect(self, url: str) -> list[dict]:
        """
        Test a URL for XSS vulnerabilities.

        Returns list of findings with type, severity, evidence, etc.
        """
        findings = []

        # Extract parameters from URL
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            # Try common parameter names
            params = {"q": ["test"], "search": ["test"], "id": ["1"],
                      "page": ["1"], "name": ["test"], "input": ["test"]}

        for param_name in params:
            # Step 1: Canary test
            canary = f"{self.CANARY}{param_name[:3]}"
            test_params = {param_name: canary}
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            test_url = f"{base}?{urlencode(test_params)}"

            resp = await self.http.get(test_url)
            if resp.error or resp.status_code == 0:
                continue

            # Check reflection
            if canary not in resp.body:
                continue

            # Step 2: Determine context
            context = self._determine_context(resp.body, canary)

            # Step 3: Test with real payloads
            payloads = self._get_context_payloads(context)

            for payload in payloads[:5]:  # Limit payloads per param
                test_params = {param_name: payload}
                payload_url = f"{base}?{urlencode(test_params)}"
                payload_resp = await self.http.get(payload_url)

                if payload_resp.error:
                    continue

                # Verify payload is present (unencoded) in response
                if self._verify_xss(payload, payload_resp.body):
                    poc = PayloadEngine.generate_poc("xss", base, param_name, payload)
                    finding = {
                        "type": "XSS (Reflected)",
                        "severity": "high",
                        "title": f"Reflected XSS in parameter '{param_name}'",
                        "description": (
                            f"The parameter '{param_name}' reflects user input in the response "
                            f"without proper sanitization. The payload '{payload}' was found "
                            f"unescaped in the response body (context: {context})."
                        ),
                        "evidence": f"Payload: {payload}\nReflection context: {context}",
                        "request": payload_url,
                        "response": payload_resp.body[:2000],
                        "reproduction": poc,
                        "confidence": "high" if context in ["script", "html_tag"] else "medium",
                    }
                    findings.append(finding)
                    logger.finding("high", "XSS", base, f"param={param_name}, context={context}")
                    break  # One finding per parameter

        # DOM XSS checks
        dom_findings = await self._check_dom_xss(url)
        findings.extend(dom_findings)

        return findings

    def _determine_context(self, body: str, canary: str) -> str:
        """Determine the reflection context of the canary."""
        for ctx_name, pattern in CONTEXT_PATTERNS.items():
            test_pattern = re.compile(pattern.pattern.replace("CANARY", re.escape(canary)))
            if test_pattern.search(body):
                return ctx_name
        return "html_body"

    def _get_context_payloads(self, context: str) -> list[str]:
        """Get payloads appropriate for the reflection context."""
        if context == "html_attr":
            return [
                '" onmouseover="alert(1)"',
                "' onmouseover='alert(1)'",
                '" onfocus="alert(1)" autofocus="',
                '"><script>alert(1)</script>',
            ]
        elif context == "script":
            return [
                "';alert(1);//",
                "\";alert(1);//",
                "</script><script>alert(1)</script>",
                "-alert(1)-",
            ]
        else:  # html_body, html_tag
            return PayloadEngine.get_payloads("xss")

    def _verify_xss(self, payload: str, body: str) -> bool:
        """Verify XSS by checking if dangerous characters survived encoding."""
        # Check for common XSS indicators in the response
        dangerous = ["<script", "onerror=", "onload=", "onmouseover=",
                      "onfocus=", "javascript:", "<img", "<svg"]
        payload_lower = payload.lower()

        for indicator in dangerous:
            if indicator in payload_lower and indicator in body.lower():
                return True

        # Direct payload reflection
        if payload in body:
            return True

        return False

    async def _check_dom_xss(self, url: str) -> list[dict]:
        """Check for potential DOM-based XSS patterns in JavaScript."""
        findings = []
        resp = await self.http.get(url)

        if resp.error or resp.status_code != 200:
            return findings

        # DOM XSS source-sink patterns
        dom_sources = [
            r'document\.URL', r'document\.documentURI', r'document\.referrer',
            r'location\.href', r'location\.search', r'location\.hash',
            r'window\.name', r'document\.cookie',
        ]
        dom_sinks = [
            r'\.innerHTML\s*=', r'\.outerHTML\s*=', r'document\.write\s*\(',
            r'document\.writeln\s*\(', r'eval\s*\(', r'setTimeout\s*\(',
            r'setInterval\s*\(', r'\.insertAdjacentHTML\s*\(',
        ]

        found_sources = []
        found_sinks = []

        for pattern in dom_sources:
            if re.search(pattern, resp.body):
                found_sources.append(pattern)

        for pattern in dom_sinks:
            if re.search(pattern, resp.body):
                found_sinks.append(pattern)

        if found_sources and found_sinks:
            findings.append({
                "type": "XSS (DOM-based, Potential)",
                "severity": "medium",
                "title": f"Potential DOM XSS detected",
                "description": (
                    f"DOM XSS sources ({', '.join(found_sources[:3])}) and "
                    f"sinks ({', '.join(found_sinks[:3])}) found in JavaScript. "
                    f"Manual verification required."
                ),
                "evidence": f"Sources: {found_sources}\nSinks: {found_sinks}",
                "request": url,
                "response": "",
                "confidence": "low",
            })

        return findings
