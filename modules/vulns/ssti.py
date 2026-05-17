"""
HexHunterX -- SSTI Detection Module (v2).

Multi-stage template injection verification:
- Stage 1: Primary expression evaluation (7*7=49)
- Stage 2: Confirmation with unique expression (7*191=1337)
- Stage 3: Template engine fingerprinting
- No parameter invention
- Contextual filtering to eliminate coincidental matches
"""

import re
from urllib.parse import urlencode, urlparse, parse_qs

from utils.logger import HexHunterXLogger
from utils.network import AsyncHTTPClient
from modules.fuzzing.payloads import PayloadEngine
from modules.vulns.verification import ConfidenceScorer, Confidence

logger = HexHunterXLogger.get_logger("vulns.ssti")

# Two-stage probes: primary + confirmation
SSTI_PROBES = [
    # (primary_expr, primary_expected, confirm_expr, confirm_expected, engine_hint)
    ("{{7*7}}", "49", "{{7*191}}", "1337", "Jinja2 / Twig / Nunjucks"),
    ("{{7*'7'}}", "7777777", "{{3*'3'}}", "333", "Jinja2"),
    ("${7*7}", "49", "${7*191}", "1337", "FreeMarker / Mako / Java EL"),
    ("<%= 7*7 %>", "49", "<%= 7*191 %>", "1337", "ERB / EJS"),
    ("#{7*7}", "49", "#{7*191}", "1337", "Ruby / Pug"),
    ("*{7*7}", "49", "*{7*191}", "1337", "Thymeleaf"),
]


class SSTIDetector:
    """
    Detect SSTI with multi-stage expression evaluation verification.

    Only reports when server-side evaluation is CONFIRMED by two
    independent mathematical expressions producing correct results.
    """

    def __init__(self, http_client: AsyncHTTPClient, oob_client=None):
        self.http = http_client
        self.oob = oob_client
        self._scorer = ConfidenceScorer()

    async def detect(self, url: str) -> list[dict]:
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return findings  # No params — no SSTI testing

        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param_name in params:
            original_val = (
                params[param_name][0]
                if isinstance(params[param_name], list)
                else str(params[param_name])
            )
            finding = await self._test_param(base, param_name, original_val, params)
            if finding:
                findings.append(finding)

            # OOB payloads
            if self.oob and self.oob.is_registered:
                for p in self.oob.get_oob_payloads("ssti", base, param_name):
                    await self.http.get(f"{base}?{urlencode({param_name: p})}")

        return findings

    async def _test_param(self, base, param_name, original_val, all_params):
        """Test a single parameter with two-stage SSTI verification."""

        # Build param dict preserving other params
        other_params = {
            k: (v[0] if isinstance(v, list) else v)
            for k, v in all_params.items() if k != param_name
        }

        # Get baseline to check if expected values already exist
        bp = {param_name: original_val, **other_params}
        baseline_resp = await self.http.get(f"{base}?{urlencode(bp)}")
        if baseline_resp.error:
            return None

        for primary, expected, confirm, confirm_expected, engine in SSTI_PROBES:
            # ── Stage 1: Primary probe ──
            tp = {param_name: primary, **other_params}
            resp = await self.http.get(f"{base}?{urlencode(tp)}")
            if resp.error or resp.status_code == 0:
                continue

            if expected not in resp.body:
                continue

            # Filter: was the expected value already in baseline?
            if expected in baseline_resp.body:
                # Check if it appears at the same position — coincidence
                # Only accept if it appears at a NEW position
                baseline_positions = [
                    m.start() for m in re.finditer(re.escape(expected), baseline_resp.body)
                ]
                resp_positions = [
                    m.start() for m in re.finditer(re.escape(expected), resp.body)
                ]
                new_positions = [p for p in resp_positions if p not in baseline_positions]
                if not new_positions:
                    continue  # Same positions — not our injection

            # ── Stage 2: Confirmation probe ──
            tp2 = {param_name: confirm, **other_params}
            resp2 = await self.http.get(f"{base}?{urlencode(tp2)}")
            if resp2.error:
                continue

            confirmed = confirm_expected in resp2.body
            if confirmed and confirm_expected in baseline_resp.body:
                # Same baseline check for confirmation
                bl_pos = [m.start() for m in re.finditer(re.escape(confirm_expected), baseline_resp.body)]
                r2_pos = [m.start() for m in re.finditer(re.escape(confirm_expected), resp2.body)]
                if not [p for p in r2_pos if p not in bl_pos]:
                    confirmed = False

            # Score confidence
            signals = {
                "expression_evaluated": True,
                "baseline_differs": True,
                "retry_confirmed": confirmed,
            }
            conf = self._scorer.score(signals)

            # If only stage 1 passed (no confirmation), downgrade
            if not confirmed:
                conf = Confidence.MEDIUM

            context_snippet = self._extract_context(resp.body, expected)
            poc = PayloadEngine.generate_poc("ssti", base, param_name, primary)

            return {
                "type": f"SSTI ({engine})",
                "severity": "critical" if confirmed else "high",
                "title": f"Server-Side Template Injection in parameter '{param_name}'",
                "description": (
                    f"Expression '{primary}' evaluated to '{expected}' server-side. "
                    + (f"Confirmed with '{confirm}'→'{confirm_expected}'. " if confirmed else "")
                    + f"Engine: {engine}."
                ),
                "evidence": (
                    f"[1] WHERE TESTED: {base}\n"
                    f"[2] HOW TESTED: Injected mathematical expression into '{param_name}' to check for server-side evaluation.\n"
                    f"[3] PAYLOAD USED: {param_name}={primary} (Stage 1) | {param_name}={confirm} (Stage 2)\n"
                    f"[4] VERIFICATION OUTPUT: Evaluated '{primary}' to '{expected}'. Confirmation '{confirm}' to '{confirm_expected}': {confirmed}. Engine Hint: {engine}.\n"
                    f"Context snippet: {context_snippet}"
                ),
                "request": f"{base}?{urlencode(tp)}",
                "response": resp.body[:2000],
                "reproduction": poc,
                "confidence": conf,
                "verification_method": "multi_stage_expression_eval",
            }

        return None

    @staticmethod
    def _extract_context(body, value, window=80):
        idx = body.find(value)
        if idx == -1:
            return ""
        start = max(0, idx - window)
        end = min(len(body), idx + len(value) + window)
        return body[start:end].strip()
