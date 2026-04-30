"""
HexHunterX -- Server-Side Request Forgery (SSRF) Detection Module.

Detect SSRF by injecting internal/cloud metadata URLs into URL-accepting
parameters and analysing responses for internal data leakage.
"""

import re
from urllib.parse import urlencode, urlparse, parse_qs

from utils.logger import HexHunterXLogger
from utils.network import AsyncHTTPClient
from modules.fuzzing.payloads import PayloadEngine

logger = HexHunterXLogger.get_logger("vulns.ssrf")

# Parameter names commonly used for URL input
URL_PARAMS = [
    "url", "link", "src", "href", "dest", "destination", "redirect",
    "redirect_url", "redirect_uri", "uri", "path", "proxy", "callback",
    "file", "page", "load", "fetch", "target", "site", "feed", "host",
    "to", "out", "view", "dir", "show", "navigation", "open", "domain",
    "source", "val", "validate", "return", "port", "data", "reference",
    "img", "image", "resource",
]

# Keywords that indicate cloud metadata was returned
METADATA_INDICATORS = [
    "ami-id", "instance-id", "instance-type", "local-hostname",
    "public-hostname", "security-credentials", "iam", "meta-data",
    "computeMetadata", "access_token", "account_id",
    "availabilityZone", "privateIp", "pendingTime",
    # Azure
    "subscriptionId", "resourceGroupName",
    # GCP
    "service-accounts", "project-id",
    # Generic internal response markers
    "root:x:", "/etc/passwd", "proc/self",
]

# Timing threshold to detect blind SSRF (ms)
TIMING_THRESHOLD_MS = 3000


class SSRFDetector:
    """
    Detect Server-Side Request Forgery vulnerabilities.

    Methodology:
        1. Identify URL-accepting parameters (from URL or common names)
        2. Inject cloud metadata URLs and internal service addresses
        3. Analyse responses for:
           a. Cloud metadata keywords (aws/gcp/azure indicators)
           b. Internal file content (/etc/passwd, /proc/self/environ)
           c. Timing anomalies (port-scan style blind SSRF)
           d. Status/size differences vs. baseline
        4. Generate PoC with reproduction steps
    """

    def __init__(self, http_client: AsyncHTTPClient, oob_client=None):
        self.http = http_client
        self.oob = oob_client

    async def detect(self, url: str) -> list[dict]:
        """Test a URL for SSRF vulnerabilities."""
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Determine which parameters to test
        test_params = self._identify_url_params(params)

        if not test_params:
            return findings

        for param_name in test_params:
            # Get baseline
            original_val = "https://example.com"
            if param_name in params and params[param_name]:
                original_val = params[param_name][0]

            baseline_url = f"{base}?{urlencode({param_name: original_val})}"
            baseline_resp = await self.http.get(baseline_url)

            if baseline_resp.error:
                continue

            # ── Standard SSRF payloads ──
            all_payloads = list(PayloadEngine.get_payloads("ssrf"))

            # ── OOB blind SSRF payloads ──
            if self.oob and self.oob.is_registered:
                oob_payloads = self.oob.get_oob_payloads("ssrf", base, param_name)
                all_payloads.extend(oob_payloads)

            for payload in all_payloads:
                test_url = f"{base}?{urlencode({param_name: payload})}"
                resp = await self.http.get(test_url)

                if resp.error:
                    continue

                # Check 1: Metadata keywords in response
                found_indicators = self._check_metadata(resp.body, baseline_resp.body)
                if found_indicators:
                    poc = PayloadEngine.generate_poc("ssrf", base, param_name, payload)
                    finding = {
                        "type": "SSRF (Data Leakage)",
                        "severity": "critical",
                        "title": f"SSRF -- internal data leaked via parameter '{param_name}'",
                        "description": (
                            f"The parameter '{param_name}' fetches attacker-controlled URLs. "
                            f"Injecting '{payload}' caused the server to return internal "
                            f"data. Detected indicators: {', '.join(found_indicators[:5])}."
                        ),
                        "evidence": (
                            f"Payload: {payload}\n"
                            f"Indicators found: {found_indicators}\n"
                            f"Response snippet: {resp.body[:1500]}"
                        ),
                        "request": test_url,
                        "response": resp.body[:3000],
                        "reproduction": poc,
                        "confidence": "high",
                    }
                    findings.append(finding)
                    logger.finding("critical", "SSRF", base, f"param={param_name}")
                    break  # One finding per param

                # Check 2: Timing anomaly (blind SSRF -- internal port responded)
                if resp.elapsed_ms > TIMING_THRESHOLD_MS and baseline_resp.elapsed_ms < TIMING_THRESHOLD_MS:
                    finding = {
                        "type": "SSRF (Blind / Timing)",
                        "severity": "medium",
                        "title": f"Potential blind SSRF via parameter '{param_name}'",
                        "description": (
                            f"The parameter '{param_name}' shows a significant response "
                            f"time increase ({resp.elapsed_ms:.0f}ms vs. baseline "
                            f"{baseline_resp.elapsed_ms:.0f}ms) when injecting internal "
                            f"addresses, suggesting the server attempts to connect."
                        ),
                        "evidence": (
                            f"Payload: {payload}\n"
                            f"Response time: {resp.elapsed_ms:.0f}ms (baseline: {baseline_resp.elapsed_ms:.0f}ms)"
                        ),
                        "request": test_url,
                        "response": "",
                        "confidence": "low",
                    }
                    findings.append(finding)
                    # Don't break -- continue looking for confirmed SSRF

                # Check 3: Response differs significantly from baseline
                #   (server fetched the URL and returned different content)
                if self._response_differs(baseline_resp, resp):
                    finding = {
                        "type": "SSRF (Potential)",
                        "severity": "high",
                        "title": f"Potential SSRF via parameter '{param_name}'",
                        "description": (
                            f"The parameter '{param_name}' returns significantly different "
                            f"content when given internal URLs. Payload: '{payload}'. "
                            f"Manual verification recommended."
                        ),
                        "evidence": (
                            f"Payload: {payload}\n"
                            f"Baseline size: {len(baseline_resp.body)}\n"
                            f"Response size: {len(resp.body)}\n"
                            f"Status: {resp.status_code}"
                        ),
                        "request": test_url,
                        "response": resp.body[:1000],
                        "confidence": "medium",
                    }
                    findings.append(finding)
                    break

        return findings

    def _identify_url_params(self, params: dict) -> list[str]:
        """Identify parameters likely to accept URLs.

        Only returns params that ALREADY exist in the query string and
        whose name or value suggests URL input.  We do NOT blindly inject
        common param names -- that causes massive false-positive floods on
        sites that ignore unknown parameters.
        """
        found = []
        for name in params:
            # Name matches a known URL-accepting pattern
            if name.lower() in URL_PARAMS:
                found.append(name)
                continue
            # Current value looks like a URL
            vals = params[name]
            if vals and isinstance(vals, list):
                val = vals[0]
                if val.startswith(("http://", "https://", "//")):
                    found.append(name)

        return list(set(found))

    @staticmethod
    def _check_metadata(body: str, baseline_body: str) -> list[str]:
        """Check response for cloud metadata or internal file indicators."""
        found = []
        body_lower = body.lower()
        baseline_lower = baseline_body.lower()

        for indicator in METADATA_INDICATORS:
            if indicator.lower() in body_lower and indicator.lower() not in baseline_lower:
                found.append(indicator)

        return found

    @staticmethod
    def _response_differs(baseline, resp) -> bool:
        """Check if the SSRF response differs meaningfully from baseline.

        Tight thresholds to avoid false positives:
        - Status code change alone is NOT enough (many sites return 200 for
          every request).
        - Requires a large absolute size difference (>500 bytes) AND a
          dramatic size ratio change.
        - Identical bodies are always safe.
        """
        if resp.body == baseline.body:
            return False

        baseline_len = max(len(baseline.body), 1)
        resp_len = len(resp.body)
        abs_diff = abs(resp_len - baseline_len)

        # Ignore small fluctuations (ads, CSRF tokens, timestamps, etc.)
        if abs_diff < 500:
            return False

        size_ratio = resp_len / baseline_len
        # Very different size = server fetched something different
        if size_ratio < 0.2 or size_ratio > 5.0:
            return True

        return False
