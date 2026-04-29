"""
HexHunter -- Server-Side Template Injection (SSTI) Detection Module.

Detect SSTI by injecting arithmetic template expressions and checking
whether the server evaluates them. Identifies Jinja2, Twig, FreeMarker,
ERB, and other engines.
"""

import re
from urllib.parse import urlencode, urlparse, parse_qs

from utils.logger import HexHunterLogger
from utils.network import AsyncHTTPClient
from modules.fuzzing.payloads import PayloadEngine

logger = HexHunterLogger.get_logger("vulns.ssti")

# Detection probes: expression -> expected computed result
SSTI_PROBES = [
    ("{{7*7}}", "49"),
    ("{{7*'7'}}", "7777777"),       # Jinja2
    ("${7*7}", "49"),               # FreeMarker / Java EL
    ("<%= 7*7 %>", "49"),           # ERB / EJS
    ("#{7*7}", "49"),               # Ruby / Pug
    ("*{7*7}", "49"),               # Thymeleaf
]

# Engine identification based on which probe triggered
ENGINE_MAP = {
    "{{7*'7'}}": "Jinja2 / Twig",
    "{{7*7}}": "Jinja2 / Twig / Nunjucks",
    "${7*7}": "FreeMarker / Mako / Java EL",
    "<%= 7*7 %>": "ERB / EJS",
    "#{7*7}": "Ruby / Slim / Pug",
    "*{7*7}": "Thymeleaf",
}


class SSTIDetector:
    """
    Detect Server-Side Template Injection vulnerabilities.

    Methodology:
        1. Inject arithmetic template expressions into all parameters
        2. Check if computed value (e.g. 49) appears in the response
        3. Validate the computed value was NOT in the baseline response
        4. Identify the template engine from the successful probe
        5. Generate PoC with engine-specific escalation payloads
    """

    def __init__(self, http_client: AsyncHTTPClient):
        self.http = http_client

    async def detect(self, url: str) -> list[dict]:
        """Test a URL for SSTI vulnerabilities."""
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            params = {
                "name": ["test"], "template": ["test"], "q": ["test"],
                "search": ["test"], "input": ["test"], "msg": ["test"],
                "message": ["test"], "text": ["test"],
            }

        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param_name in params:
            # Get baseline response
            original_val = params[param_name][0] if isinstance(params[param_name], list) else str(params[param_name])
            baseline_url = f"{base}?{urlencode({param_name: original_val})}"
            baseline_resp = await self.http.get(baseline_url)

            if baseline_resp.error:
                continue

            # Test each probe
            for probe, expected in SSTI_PROBES:
                test_url = f"{base}?{urlencode({param_name: probe})}"
                resp = await self.http.get(test_url)

                if resp.error or resp.status_code == 0:
                    continue

                # Check if computed value appears in response but NOT in baseline
                if expected in resp.body and expected not in baseline_resp.body:
                    engine = ENGINE_MAP.get(probe, "Unknown")
                    poc = PayloadEngine.generate_poc("ssti", base, param_name, probe)

                    finding = {
                        "type": f"SSTI ({engine})",
                        "severity": "critical",
                        "title": f"Server-Side Template Injection in parameter '{param_name}'",
                        "description": (
                            f"The parameter '{param_name}' is vulnerable to Server-Side "
                            f"Template Injection. The expression '{probe}' was evaluated "
                            f"server-side, producing '{expected}' in the response. "
                            f"Detected engine: {engine}. This can lead to Remote Code Execution."
                        ),
                        "evidence": (
                            f"Probe: {probe}\n"
                            f"Expected: {expected}\n"
                            f"Engine: {engine}\n"
                            f"Response snippet: {self._extract_context(resp.body, expected)}"
                        ),
                        "request": test_url,
                        "response": resp.body[:2000],
                        "reproduction": poc,
                        "confidence": "high",
                    }
                    findings.append(finding)
                    logger.finding("critical", "SSTI", base,
                                   f"param={param_name}, engine={engine}")
                    break  # One finding per parameter

        return findings

    @staticmethod
    def _extract_context(body: str, value: str, window: int = 80) -> str:
        """Extract a snippet of the response around the computed value."""
        idx = body.find(value)
        if idx == -1:
            return ""
        start = max(0, idx - window)
        end = min(len(body), idx + len(value) + window)
        return body[start:end].strip()
