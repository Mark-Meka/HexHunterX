"""
HexHunterX -- Finding Deduplication Engine.

Prevents duplicate vulnerability findings across detectors, URLs,
and scan phases using request fingerprinting and severity-based merging.
"""

import hashlib
import re
from urllib.parse import urlparse, parse_qs, urlencode

from utils.logger import HexHunterXLogger
from modules.vulns.verification import Confidence

logger = HexHunterXLogger.get_logger("vulns.deduplication")

# Severity ranking for dedup (keep highest)
_SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class FindingDeduplicator:
    """
    Deduplicate vulnerability findings to eliminate redundant reports.

    Deduplication strategy:
    1. Fingerprint each finding by (vuln_type_normalized, host, path, parameter).
    2. If two findings share the same fingerprint, keep the one with
       higher severity and confidence.
    3. Cross-detector dedup: e.g. CORS from misconfig.py and cors.py.
    4. Per-host limits: max N findings per host to prevent noise floods.
    """

    def __init__(self, max_findings: int = 50, max_per_host: int = 20,
                 min_confidence: str = "medium"):
        self.max_findings = max_findings
        self.max_per_host = max_per_host
        self.min_confidence = min_confidence
        self._seen: dict[str, dict] = {}  # fingerprint -> best finding
        self._host_counts: dict[str, int] = {}

    def fingerprint(self, finding: dict) -> str:
        """
        Generate a unique fingerprint for a finding.

        Based on: normalized vuln type + host + path + parameter.
        """
        vuln_type = self._normalize_type(finding.get("type", ""))
        url = finding.get("request", "")
        # Extract URL from request string (might be prefixed with method)
        url_match = re.search(r'https?://\S+', url)
        if url_match:
            url = url_match.group(0)

        try:
            parsed = urlparse(url)
            host = parsed.hostname or ""
            path = parsed.path or "/"
        except Exception:
            host = ""
            path = "/"

        # Extract parameter name from title or evidence
        param = ""
        title = finding.get("title", "")
        param_match = re.search(r"parameter\s+'(\w+)'", title)
        if param_match:
            param = param_match.group(1)

        raw = f"{vuln_type}|{host}|{path}|{param}"
        return hashlib.md5(raw.encode()).hexdigest()

    def _normalize_type(self, vuln_type: str) -> str:
        """Normalize vulnerability type for dedup comparison."""
        t = vuln_type.lower()
        # Collapse subtypes
        if "xss" in t:
            return "xss"
        if "sqli" in t or "sql injection" in t:
            return "sqli"
        if "redirect" in t:
            return "redirect"
        if "idor" in t:
            return "idor"
        if "ssti" in t or "template" in t:
            return "ssti"
        if "ssrf" in t:
            return "ssrf"
        if "nosql" in t:
            return "nosqli"
        if "csrf" in t:
            return "csrf"
        if "cors" in t:
            return "cors"
        if "header" in t or "misconfig" in t:
            return "misconfig"
        return t

    def _get_host(self, finding: dict) -> str:
        """Extract host from finding request URL."""
        url = finding.get("request", "")
        url_match = re.search(r'https?://\S+', url)
        if url_match:
            try:
                return urlparse(url_match.group(0)).hostname or ""
            except Exception:
                pass
        return ""

    def add(self, finding: dict) -> bool:
        """
        Attempt to add a finding. Returns True if accepted, False if deduped.

        Applies:
        - Confidence threshold filtering
        - Fingerprint-based dedup (keep best)
        - Per-host limits
        - Global finding limit
        """
        # Filter by minimum confidence
        confidence = finding.get("confidence", "medium")
        if not Confidence.meets_threshold(confidence, self.min_confidence):
            logger.debug(
                f"Finding dropped (confidence={confidence} < {self.min_confidence}): "
                f"{finding.get('title', '')[:80]}"
            )
            return False

        fp = self.fingerprint(finding)
        host = self._get_host(finding)

        # Fingerprint dedup: keep the one with higher severity + confidence
        if fp in self._seen:
            existing = self._seen[fp]
            existing_rank = (
                _SEVERITY_RANK.get(existing.get("severity", "info"), 0),
                Confidence.RANK.get(existing.get("confidence", "low"), 0),
            )
            new_rank = (
                _SEVERITY_RANK.get(finding.get("severity", "info"), 0),
                Confidence.RANK.get(finding.get("confidence", "low"), 0),
            )
            if new_rank > existing_rank:
                self._seen[fp] = finding
                logger.debug(f"Finding upgraded (better severity/confidence): {fp[:12]}")
            else:
                logger.debug(f"Finding deduped (same or lower rank): {fp[:12]}")
            return False

        # Per-host limit
        host_count = self._host_counts.get(host, 0)
        if host_count >= self.max_per_host:
            logger.debug(f"Finding dropped (host limit {self.max_per_host}): {host}")
            return False

        # Global limit
        if len(self._seen) >= self.max_findings:
            logger.debug("Finding dropped (global limit reached)")
            return False

        # Accept
        self._seen[fp] = finding
        self._host_counts[host] = host_count + 1
        return True

    def get_findings(self) -> list[dict]:
        """Return all accepted findings, sorted by severity (critical first)."""
        findings = list(self._seen.values())
        findings.sort(
            key=lambda f: (
                -_SEVERITY_RANK.get(f.get("severity", "info"), 0),
                -Confidence.RANK.get(f.get("confidence", "low"), 0),
            )
        )
        return findings

    @property
    def stats(self) -> dict:
        return {
            "total_accepted": len(self._seen),
            "hosts": dict(self._host_counts),
        }

    def reset(self):
        self._seen.clear()
        self._host_counts.clear()
