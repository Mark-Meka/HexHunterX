"""
HexHunterX -- Centralized Verification Framework.

Provides response diffing, timing analysis, confidence scoring,
baseline management, and response normalization to eliminate
false positives across all vulnerability detection modules.
"""

import hashlib
import re
import time
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any

from utils.logger import HexHunterXLogger

logger = HexHunterXLogger.get_logger("vulns.verification")


# ── Confidence Levels ─────────────────────────────────────────────────
class Confidence:
    """Four-tier confidence system for vulnerability findings."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"

    RANK = {LOW: 1, MEDIUM: 2, HIGH: 3, CONFIRMED: 4}

    @classmethod
    def meets_threshold(cls, confidence: str, threshold: str) -> bool:
        return cls.RANK.get(confidence, 0) >= cls.RANK.get(threshold, 0)

    @classmethod
    def highest(cls, *levels: str) -> str:
        best = cls.LOW
        for lvl in levels:
            if cls.RANK.get(lvl, 0) > cls.RANK.get(best, 0):
                best = lvl
        return best


# ── Response Normalizer ───────────────────────────────────────────────
# Regex patterns for dynamic content that should be stripped before comparison.
_DYNAMIC_PATTERNS = [
    # CSRF / nonce tokens (hex strings in hidden inputs)
    re.compile(
        r'(<input[^>]*(?:name|id)=["\'](?:csrf|_csrf|_token|nonce|xsrf|'
        r'authenticity_token|__RequestVerificationToken)["\'][^>]*value=["\'])'
        r'[A-Fa-f0-9\-]{8,}(["\'])',
        re.IGNORECASE,
    ),
    # Session IDs in cookies / hidden fields
    re.compile(r'(?:session|sess|sid|PHPSESSID|JSESSIONID)=[A-Za-z0-9\-_.]{8,}', re.IGNORECASE),
    # ISO timestamps
    re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?'),
    # Unix timestamps (10-13 digits)
    re.compile(r'(?<![A-Za-z0-9])\d{10,13}(?![A-Za-z0-9])'),
    # Random hex / base64 tokens (standalone, 16+ chars)
    re.compile(r'(?<![A-Za-z0-9/+])[A-Fa-f0-9]{32,}(?![A-Za-z0-9/+])'),
]


class ResponseNormalizer:
    """Strip dynamic content from HTTP response bodies for stable comparison."""

    @staticmethod
    def normalize(body: str) -> str:
        """Return a normalized body with dynamic tokens replaced by placeholders."""
        result = body
        for pattern in _DYNAMIC_PATTERNS:
            result = pattern.sub("[DYNAMIC]", result)
        # Collapse multiple whitespace
        result = re.sub(r'\s+', ' ', result).strip()
        return result

    @staticmethod
    def structural_hash(body: str) -> str:
        """Hash the structural skeleton of an HTML response (tags only)."""
        tags_only = re.sub(r'>[^<]+<', '><', body)
        tags_only = re.sub(r'\s+', '', tags_only)
        return hashlib.md5(tags_only.encode(errors="replace")).hexdigest()


# ── Response Analyzer ─────────────────────────────────────────────────
class ResponseAnalyzer:
    """
    Compare HTTP responses to detect meaningful behavioral changes.

    Uses normalized body comparison, structural similarity,
    status code analysis, and content-length diffing.
    """

    def __init__(self, similarity_threshold: float = 0.85):
        self.similarity_threshold = similarity_threshold
        self._normalizer = ResponseNormalizer()

    def similarity(self, body_a: str, body_b: str) -> float:
        """
        Return similarity ratio (0.0 – 1.0) between two response bodies
        after normalization.
        """
        norm_a = self._normalizer.normalize(body_a)
        norm_b = self._normalizer.normalize(body_b)
        if norm_a == norm_b:
            return 1.0
        # SequenceMatcher on large bodies is O(n²) — sample if huge
        if len(norm_a) > 50_000 or len(norm_b) > 50_000:
            norm_a = norm_a[:50_000]
            norm_b = norm_b[:50_000]
        return SequenceMatcher(None, norm_a, norm_b).ratio()

    def is_same_response(self, body_a: str, body_b: str) -> bool:
        """Return True if responses are functionally identical."""
        return self.similarity(body_a, body_b) >= self.similarity_threshold

    def diff_summary(self, body_a: str, body_b: str) -> dict:
        """Return a summary of how two responses differ."""
        sim = self.similarity(body_a, body_b)
        len_a = len(body_a)
        len_b = len(body_b)
        return {
            "similarity": round(sim, 4),
            "length_a": len_a,
            "length_b": len_b,
            "length_diff": abs(len_a - len_b),
            "structural_match": (
                ResponseNormalizer.structural_hash(body_a)
                == ResponseNormalizer.structural_hash(body_b)
            ),
        }

    def response_changed_meaningfully(self, baseline_body: str, test_body: str,
                                       min_diff_bytes: int = 200) -> bool:
        """
        Return True if the test response differs meaningfully from baseline.

        Criteria:
        - Not functionally identical (after normalization)
        - Absolute size difference > min_diff_bytes
        """
        if self.is_same_response(baseline_body, test_body):
            return False
        if abs(len(baseline_body) - len(test_body)) < min_diff_bytes:
            return False
        return True


# ── Timing Analyzer ───────────────────────────────────────────────────
@dataclass
class TimingResult:
    """Result of a timing-based verification attempt."""
    is_significant: bool = False
    baseline_median_ms: float = 0.0
    injected_median_ms: float = 0.0
    delay_ms: float = 0.0
    trials: int = 0
    consistent: bool = False


class TimingAnalyzer:
    """
    Detect timing-based vulnerabilities with statistical rigor.

    Requires consistent timing differences across multiple trials
    to eliminate network jitter false positives.
    """

    def __init__(self, threshold_ms: float = 5000.0, trials: int = 3,
                 jitter_tolerance: float = 0.3):
        self.threshold_ms = threshold_ms
        self.trials = trials
        self.jitter_tolerance = jitter_tolerance

    async def verify_timing(self, http_client, baseline_url: str,
                            injected_url: str) -> TimingResult:
        """
        Verify if injected URL consistently shows timing delay.

        Sends `self.trials` requests to both baseline and injected URLs,
        compares median response times.
        """
        baseline_times = []
        injected_times = []

        for _ in range(self.trials):
            # Baseline request
            resp = await http_client.get(baseline_url)
            if not resp.error:
                baseline_times.append(resp.elapsed_ms)

            # Injected request
            resp = await http_client.get(injected_url)
            if not resp.error:
                injected_times.append(resp.elapsed_ms)

        if len(baseline_times) < 2 or len(injected_times) < 2:
            return TimingResult(trials=len(injected_times))

        baseline_median = sorted(baseline_times)[len(baseline_times) // 2]
        injected_median = sorted(injected_times)[len(injected_times) // 2]
        delay = injected_median - baseline_median

        # Check if delay is significant
        is_significant = delay >= self.threshold_ms

        # Check consistency: all injected times should exceed threshold
        consistent = all(
            t > baseline_median + (self.threshold_ms * (1 - self.jitter_tolerance))
            for t in injected_times
        )

        return TimingResult(
            is_significant=is_significant and consistent,
            baseline_median_ms=round(baseline_median, 2),
            injected_median_ms=round(injected_median, 2),
            delay_ms=round(delay, 2),
            trials=len(injected_times),
            consistent=consistent,
        )


# ── Baseline Manager ──────────────────────────────────────────────────
class BaselineManager:
    """
    Capture and cache baseline responses to avoid redundant requests.

    Caches by (normalized_url, param_name) so each parameter's baseline
    is captured once per scan.
    """

    def __init__(self, http_client):
        self.http = http_client
        self._cache: dict[str, Any] = {}

    def _cache_key(self, url: str, param: str = "") -> str:
        return f"{url}|{param}"

    async def get_baseline(self, url: str, param: str = ""):
        """Get or fetch the baseline response for a URL+param combination."""
        key = self._cache_key(url, param)
        if key not in self._cache:
            resp = await self.http.get(url)
            self._cache[key] = resp
        return self._cache[key]

    def clear(self):
        self._cache.clear()


# ── Confidence Scorer ─────────────────────────────────────────────────
class ConfidenceScorer:
    """
    Combine multiple verification signals into a single confidence level.

    Each signal contributes a weighted score. The final score maps
    to a confidence tier.
    """

    # Signal weights (0.0 – 1.0)
    SIGNAL_WEIGHTS = {
        "reflection_in_executable_context": 0.35,
        "behavioral_change": 0.25,
        "timing_verified": 0.30,
        "retry_confirmed": 0.20,
        "error_pattern_match": 0.20,
        "baseline_differs": 0.15,
        "sanitization_absent": 0.15,
        "context_breakout": 0.25,
        "expression_evaluated": 0.35,
        "auth_bypass": 0.40,
        "redirect_confirmed": 0.30,
        "metadata_leaked": 0.40,
        "sensitive_data_exposed": 0.30,
        "status_code_flip": 0.20,
    }

    # Score thresholds for confidence tiers
    THRESHOLDS = {
        Confidence.CONFIRMED: 0.70,
        Confidence.HIGH: 0.50,
        Confidence.MEDIUM: 0.30,
        Confidence.LOW: 0.0,
    }

    def score(self, signals: dict[str, bool]) -> str:
        """
        Calculate confidence from a dict of signal_name -> True/False.

        Returns one of: 'confirmed', 'high', 'medium', 'low'.
        """
        total = 0.0
        for signal, active in signals.items():
            if active and signal in self.SIGNAL_WEIGHTS:
                total += self.SIGNAL_WEIGHTS[signal]

        if total >= self.THRESHOLDS[Confidence.CONFIRMED]:
            return Confidence.CONFIRMED
        elif total >= self.THRESHOLDS[Confidence.HIGH]:
            return Confidence.HIGH
        elif total >= self.THRESHOLDS[Confidence.MEDIUM]:
            return Confidence.MEDIUM
        return Confidence.LOW

    def explain(self, signals: dict[str, bool]) -> str:
        """Return a human-readable explanation of the confidence scoring."""
        active = [s for s, v in signals.items() if v and s in self.SIGNAL_WEIGHTS]
        inactive = [s for s, v in signals.items() if not v and s in self.SIGNAL_WEIGHTS]
        confidence = self.score(signals)
        parts = [f"Confidence: {confidence}"]
        if active:
            parts.append(f"  Verified: {', '.join(active)}")
        if inactive:
            parts.append(f"  Not met: {', '.join(inactive)}")
        return "\n".join(parts)
