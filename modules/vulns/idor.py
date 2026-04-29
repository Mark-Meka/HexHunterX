"""
HexHunter -- IDOR Detection Module.

Detect Insecure Direct Object Reference patterns via sequential ID testing.
"""

import re
from urllib.parse import urlencode, urlparse, parse_qs

from utils.logger import HexHunterLogger
from utils.network import AsyncHTTPClient

logger = HexHunterLogger.get_logger("vulns.idor")

# Patterns that commonly contain object references
IDOR_PARAM_PATTERNS = [
    r'id', r'user_id', r'uid', r'account', r'profile', r'order',
    r'doc', r'file', r'item', r'product', r'invoice', r'report',
    r'ticket', r'message', r'msg', r'comment', r'post',
]


class IDORDetector:
    """
    Detect IDOR patterns by analyzing URL structures and parameter values.

    Methodology:
        1. Identify numeric/sequential ID parameters
        2. Test with adjacent IDs (id-1, id+1)
        3. Compare response sizes and status codes
        4. Flag if different objects are returned for adjacent IDs
    """

    def __init__(self, http_client: AsyncHTTPClient):
        self.http = http_client

    async def detect(self, url: str) -> list[dict]:
        """Test URL for IDOR patterns."""
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Also check path-based IDs (e.g., /api/users/123)
        path_findings = self._check_path_idor(parsed.path, base)
        findings.extend(path_findings)

        # Check query parameter IDs
        for param, values in params.items():
            if not self._is_id_param(param, values):
                continue

            original_val = values[0]
            try:
                int_val = int(original_val)
            except ValueError:
                continue

            # Test adjacent IDs
            test_ids = [int_val - 1, int_val + 1, int_val + 100]

            # Get baseline response
            baseline_resp = await self.http.get(url)
            if baseline_resp.error:
                continue

            for test_id in test_ids:
                test_params = {param: str(test_id)}
                other_params = {k: v[0] for k, v in params.items() if k != param}
                test_params.update(other_params)
                test_url = f"{base}?{urlencode(test_params)}"

                resp = await self.http.get(test_url)
                if resp.error:
                    continue

                # IDOR indicators:
                # 1. Different content returned (200 with different body)
                # 2. Response with sensitive data for different user
                if self._compare_responses(baseline_resp, resp, original_val, str(test_id)):
                    finding = {
                        "type": "IDOR (Potential)",
                        "severity": "high",
                        "title": f"Potential IDOR in parameter '{param}'",
                        "description": (
                            f"Parameter '{param}' accepts sequential numeric IDs. "
                            f"Changing from {original_val} to {test_id} returned a "
                            f"valid response with different content, suggesting "
                            f"potential IDOR. Manual verification required."
                        ),
                        "evidence": (
                            f"Original ID: {original_val} → Status: {baseline_resp.status_code}, "
                            f"Size: {len(baseline_resp.body)}\n"
                            f"Test ID: {test_id} → Status: {resp.status_code}, "
                            f"Size: {len(resp.body)}"
                        ),
                        "request": test_url,
                        "response": resp.body[:1000],
                        "confidence": "medium",
                    }
                    findings.append(finding)
                    logger.finding("high", "IDOR", base, f"param={param}, id={test_id}")
                    break

        return findings

    def _is_id_param(self, param: str, values: list) -> bool:
        """Check if a parameter name and value suggest an object ID."""
        param_lower = param.lower()
        for pattern in IDOR_PARAM_PATTERNS:
            if re.search(pattern, param_lower, re.IGNORECASE):
                return True
        # Check if value is numeric
        if values and values[0].isdigit():
            return True
        return False

    def _compare_responses(self, baseline, test_resp, orig_id: str, test_id: str) -> bool:
        """Compare responses to determine if IDOR might exist."""
        # Both must return 200
        if test_resp.status_code != 200:
            return False

        # Must have meaningful content
        if len(test_resp.body) < 100:
            return False

        # Bodies must differ (different objects)
        if baseline.body == test_resp.body:
            return False

        # Size difference should be reasonable (not a generic error page)
        size_ratio = len(test_resp.body) / max(len(baseline.body), 1)
        if size_ratio < 0.3 or size_ratio > 3.0:
            return False

        return True

    def _check_path_idor(self, path: str, base: str) -> list[dict]:
        """Check for path-based IDOR patterns (e.g., /users/123)."""
        findings = []
        # Detect paths like /resource/123
        pattern = re.compile(r'/([a-zA-Z]+)/(\d+)')
        matches = pattern.findall(path)

        for resource, id_val in matches:
            findings.append({
                "type": "IDOR (Pattern)",
                "severity": "info",
                "title": f"Sequential ID pattern in path: /{resource}/{id_val}",
                "description": (
                    f"URL path contains sequential numeric ID for resource '{resource}'. "
                    f"This pattern is commonly associated with IDOR vulnerabilities. "
                    f"Manual testing with different IDs is recommended."
                ),
                "evidence": f"Path pattern: /{resource}/{id_val}",
                "request": f"{base}",
                "confidence": "low",
            })

        return findings
