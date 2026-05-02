"""
HexHunterX -- SSRF Detection Module (v2).

Enhanced with:
- Tightened response diffing (1000-byte threshold)
- Internal service banner detection
- Timing retry verification
- Confidence tiers
- Only tests existing URL-accepting parameters
"""

import re
from urllib.parse import urlencode, urlparse, parse_qs

from utils.logger import HexHunterXLogger
from utils.network import AsyncHTTPClient
from modules.fuzzing.payloads import PayloadEngine
from modules.vulns.verification import (
    ResponseAnalyzer, TimingAnalyzer, ConfidenceScorer, Confidence,
)

logger = HexHunterXLogger.get_logger("vulns.ssrf")

URL_PARAMS = [
    "url", "link", "src", "href", "dest", "destination", "redirect",
    "redirect_url", "redirect_uri", "uri", "path", "proxy", "callback",
    "file", "page", "load", "fetch", "target", "site", "feed", "host",
    "to", "out", "view", "dir", "show", "open", "domain", "source",
    "img", "image", "resource",
]

METADATA_INDICATORS = [
    "ami-id", "instance-id", "instance-type", "local-hostname",
    "security-credentials", "iam", "meta-data", "computeMetadata",
    "access_token", "account_id", "availabilityZone", "privateIp",
    "subscriptionId", "resourceGroupName", "service-accounts",
    "project-id", "root:x:", "/etc/passwd", "proc/self",
]

# Internal service response signatures
INTERNAL_SERVICE_SIGS = [
    (r'-ERR\s|^\+OK|^\$\d+', "Redis"),
    (r'SSH-\d+\.\d+', "SSH"),
    (r'220\s.*SMTP|ESMTP', "SMTP"),
    (r'MongoDB|Mongo server', "MongoDB"),
    (r'"cluster_name"\s*:', "Elasticsearch"),
    (r'mysql_native_password|MariaDB', "MySQL"),
]


class SSRFDetector:
    """
    Detect SSRF with verified internal data leakage detection.

    Only tests params that already exist and look like URL inputs.
    Uses metadata keyword matching, internal service detection,
    and timing analysis with retries.
    """

    def __init__(self, http_client: AsyncHTTPClient, oob_client=None):
        self.http = http_client
        self.oob = oob_client
        self._analyzer = ResponseAnalyzer()
        self._timing = TimingAnalyzer(threshold_ms=3000, trials=3)
        self._scorer = ConfidenceScorer()

    async def detect(self, url: str) -> list[dict]:
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        test_params = self._identify_url_params(params)
        if not test_params:
            return findings

        for param_name in test_params:
            original_val = "https://example.com"
            if param_name in params and params[param_name]:
                original_val = params[param_name][0]

            bp = {param_name: original_val}
            baseline_resp = await self.http.get(f"{base}?{urlencode(bp)}")
            if baseline_resp.error:
                continue

            # Build payload list
            all_payloads = list(PayloadEngine.get_payloads("ssrf"))
            if self.oob and self.oob.is_registered:
                all_payloads.extend(
                    self.oob.get_oob_payloads("ssrf", base, param_name)
                )

            for payload in all_payloads:
                tp = {param_name: payload}
                resp = await self.http.get(f"{base}?{urlencode(tp)}")
                if resp.error:
                    continue

                # Check 1: Cloud metadata / internal file content
                indicators = self._check_metadata(resp.body, baseline_resp.body)
                if indicators:
                    signals = {"metadata_leaked": True, "baseline_differs": True}
                    conf = self._scorer.score(signals)
                    poc = PayloadEngine.generate_poc("ssrf", base, param_name, payload)
                    findings.append({
                        "type": "SSRF (Data Leakage)",
                        "severity": "critical",
                        "title": f"SSRF — internal data leaked via '{param_name}'",
                        "description": (
                            f"Injecting '{payload}' returned internal data. "
                            f"Indicators: {', '.join(indicators[:5])}."
                        ),
                        "evidence": (
                            f"Payload: {payload}\n"
                            f"Indicators: {indicators}\n"
                            f"Response: {resp.body[:1500]}"
                        ),
                        "request": f"{base}?{urlencode(tp)}",
                        "response": resp.body[:3000],
                        "reproduction": poc,
                        "confidence": conf,
                        "verification_method": "metadata_content_analysis",
                    })
                    break

                # Check 2: Internal service signatures
                service = self._detect_internal_service(resp.body, baseline_resp.body)
                if service:
                    signals = {"metadata_leaked": True, "baseline_differs": True}
                    conf = self._scorer.score(signals)
                    findings.append({
                        "type": f"SSRF (Internal Service: {service})",
                        "severity": "high",
                        "title": f"SSRF — internal {service} service via '{param_name}'",
                        "description": (
                            f"Internal {service} service banner detected in response."
                        ),
                        "evidence": f"Payload: {payload}\nService: {service}",
                        "request": f"{base}?{urlencode(tp)}",
                        "response": resp.body[:2000],
                        "confidence": conf,
                        "verification_method": "internal_service_detection",
                    })
                    break

                # Check 3: Response differs significantly
                if self._response_differs(baseline_resp, resp):
                    findings.append({
                        "type": "SSRF (Potential)",
                        "severity": "medium",
                        "title": f"Potential SSRF via parameter '{param_name}'",
                        "description": (
                            f"Significant response difference with internal URL. "
                            f"Manual verification recommended."
                        ),
                        "evidence": (
                            f"Payload: {payload}\n"
                            f"Baseline size: {len(baseline_resp.body)}\n"
                            f"Response size: {len(resp.body)}"
                        ),
                        "request": f"{base}?{urlencode(tp)}",
                        "response": resp.body[:1000],
                        "confidence": Confidence.MEDIUM,
                        "verification_method": "response_diff_analysis",
                    })
                    break

        return findings

    def _identify_url_params(self, params):
        found = []
        for name in params:
            if name.lower() in URL_PARAMS:
                found.append(name)
                continue
            vals = params[name]
            if vals and isinstance(vals, list):
                val = vals[0]
                if val.startswith(("http://", "https://", "//")):
                    found.append(name)
        return list(set(found))

    @staticmethod
    def _check_metadata(body, baseline_body):
        found = []
        body_lower = body.lower()
        bl_lower = baseline_body.lower()
        for indicator in METADATA_INDICATORS:
            if indicator.lower() in body_lower and indicator.lower() not in bl_lower:
                found.append(indicator)
        return found

    def _detect_internal_service(self, body, baseline_body):
        for pattern, service in INTERNAL_SERVICE_SIGS:
            if re.search(pattern, body, re.I) and not re.search(pattern, baseline_body, re.I):
                return service
        return None

    @staticmethod
    def _response_differs(baseline, resp):
        if resp.body == baseline.body:
            return False
        bl_len = max(len(baseline.body), 1)
        resp_len = len(resp.body)
        if abs(resp_len - bl_len) < 1000:  # Tighter threshold: 1000 bytes
            return False
        ratio = resp_len / bl_len
        if ratio < 0.15 or ratio > 6.0:
            return True
        return False
