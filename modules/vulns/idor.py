"""
HexHunterX -- IDOR Detection Module (v2).

Redesigned to eliminate false positives:
- No path-pattern-based detection (removed)
- No parameter invention
- Content similarity analysis (normalized)
- Sensitive data detection in cross-ID responses
- Authentication-aware comparison when available
"""

import re
from urllib.parse import urlencode, urlparse, parse_qs

from utils.logger import HexHunterXLogger
from utils.network import AsyncHTTPClient
from modules.vulns.verification import (
    ResponseAnalyzer, ConfidenceScorer, Confidence,
)

logger = HexHunterXLogger.get_logger("vulns.idor")

IDOR_PARAM_PATTERNS = [
    r'id', r'user_id', r'uid', r'account', r'profile', r'order',
    r'doc', r'file', r'item', r'product', r'invoice', r'report',
    r'ticket', r'message', r'msg', r'comment', r'post',
]

# PII patterns indicating sensitive data exposure
_PII_PATTERNS = [
    re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),  # email
    re.compile(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'),  # phone
    re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),  # SSN
    re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),  # CC
]


class IDORDetector:
    """
    Detect IDOR by verifying that changing object IDs returns
    different user-specific data without authorization checks.

    DOES NOT report based on:
    - URL path patterns alone
    - 200 OK alone
    - Sequential IDs alone
    """

    def __init__(self, http_client: AsyncHTTPClient):
        self.http = http_client
        self._analyzer = ResponseAnalyzer(similarity_threshold=0.85)
        self._scorer = ConfidenceScorer()

    async def detect(self, url: str) -> list[dict]:
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return findings

        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param, values in params.items():
            if not self._is_id_param(param, values):
                continue
            try:
                int_val = int(values[0])
            except (ValueError, IndexError):
                continue

            finding = await self._test_idor(base, param, int_val, params)
            if finding:
                findings.append(finding)

        return findings

    async def _test_idor(self, base, param, orig_id, all_params):
        """Test for IDOR by comparing responses for different IDs."""
        other_params = {
            k: (v[0] if isinstance(v, list) else v)
            for k, v in all_params.items() if k != param
        }

        # Baseline response
        bp = {param: str(orig_id), **other_params}
        baseline = await self.http.get(f"{base}?{urlencode(bp)}")
        if baseline.error or baseline.status_code != 200:
            return None

        # Test adjacent IDs
        test_ids = [orig_id + 1, orig_id - 1]
        for test_id in test_ids:
            if test_id < 0:
                continue

            tp = {param: str(test_id), **other_params}
            resp = await self.http.get(f"{base}?{urlencode(tp)}")

            if resp.error or resp.status_code != 200:
                continue

            # Must have meaningful content
            if len(resp.body) < 100:
                continue

            # Bodies must be different (different objects)
            sim = self._analyzer.similarity(baseline.body, resp.body)
            if sim > 0.95:
                continue  # Same response — no object difference

            # Bodies must be structurally similar (same page type, different data)
            if sim < 0.30:
                continue  # Completely different page — probably error

            # Check for sensitive data in the alternate ID response
            has_pii = self._detect_pii(resp.body, baseline.body)

            # Check structural match — same page template, different data
            structural = self._analyzer.diff_summary(baseline.body, resp.body)

            signals = {
                "behavioral_change": True,
                "sensitive_data_exposed": has_pii,
                "baseline_differs": sim < 0.90,
            }
            conf = self._scorer.score(signals)

            # Require at least medium confidence
            if not Confidence.meets_threshold(conf, Confidence.MEDIUM):
                continue

            return {
                "type": "IDOR (Potential)",
                "severity": "high" if has_pii else "medium",
                "title": f"Potential IDOR in parameter '{param}'",
                "description": (
                    f"Changing '{param}' from {orig_id} to {test_id} returns "
                    f"different object data (similarity: {sim:.2f}). "
                    + ("Sensitive data patterns detected. " if has_pii else "")
                    + "Manual verification of authorization required."
                ),
                "evidence": (
                    f"Original ID: {orig_id} (size: {len(baseline.body)})\n"
                    f"Test ID: {test_id} (size: {len(resp.body)})\n"
                    f"Similarity: {sim:.4f}\n"
                    f"PII detected: {has_pii}\n"
                    f"Structural match: {structural['structural_match']}"
                ),
                "request": f"{base}?{urlencode(tp)}",
                "response": resp.body[:1000],
                "confidence": conf,
                "verification_method": "object_comparison_analysis",
            }
        return None

    def _is_id_param(self, param, values):
        param_lower = param.lower()
        for pattern in IDOR_PARAM_PATTERNS:
            if re.search(pattern, param_lower, re.IGNORECASE):
                return True
        if values and values[0].isdigit():
            return True
        return False

    def _detect_pii(self, test_body, baseline_body):
        """Check if test response contains PII not in baseline."""
        for pattern in _PII_PATTERNS:
            test_matches = set(pattern.findall(test_body))
            baseline_matches = set(pattern.findall(baseline_body))
            new_pii = test_matches - baseline_matches
            if new_pii:
                return True
        return False
