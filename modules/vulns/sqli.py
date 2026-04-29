"""
HexHunter -- SQL Injection Detection Module.

Error-based SQL injection detection with multi-database support.
"""

import re
from urllib.parse import urlencode, urlparse, parse_qs

from utils.logger import HexHunterLogger
from utils.network import AsyncHTTPClient
from modules.fuzzing.payloads import PayloadEngine

logger = HexHunterLogger.get_logger("vulns.sqli")

# Database error patterns for identification
DB_ERROR_PATTERNS = {
    "MySQL": [
        r"SQL syntax.*?MySQL",
        r"Warning.*?\Wmysqli?_",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that corresponds to your MySQL",
        r"Unknown column.*?in 'field list'",
        r"MySqlClient\.",
    ],
    "PostgreSQL": [
        r"PostgreSQL.*?ERROR",
        r"Warning.*?\Wpg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError:",
        r"org\.postgresql\.util\.PSQLException",
    ],
    "MSSQL": [
        r"Driver.*? SQL[\-\_\ ]*Server",
        r"OLE DB.*? SQL Server",
        r"\bSQL Server\b.*?\bDriver",
        r"Warning.*?\W(mssql|sqlsrv)_",
        r"\bSQL Server\b.*?Error",
        r"Microsoft SQL Native Client.*?Error",
        r"ODBC SQL Server Driver",
    ],
    "Oracle": [
        r"\bORA-\d{5}",
        r"Oracle error",
        r"Oracle.*?Driver",
        r"Warning.*?\Woci_",
        r"quoted string not properly terminated",
    ],
    "SQLite": [
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*?\Wsqlite_",
        r"SQLite error",
        r"\[SQLITE_ERROR\]",
    ],
}


class SQLiDetector:
    """
    Detect SQL injection vulnerabilities via error-based testing.

    Methodology:
        1. Inject SQL metacharacters to trigger errors
        2. Analyze response for database error patterns
        3. Identify database type from error signature
        4. Validate findings to reduce false positives
        5. Generate PoC and suggest further testing
    """

    def __init__(self, http_client: AsyncHTTPClient, oob_client=None):
        self.http = http_client
        self.oob = oob_client

    async def detect(self, url: str) -> list[dict]:
        """Test a URL for SQL injection vulnerabilities."""
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            params = {"id": ["1"], "page": ["1"], "item": ["1"]}

        for param_name in params:
            # Get baseline
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            original_val = params[param_name][0] if params[param_name] else "1"
            baseline_url = f"{base}?{urlencode({param_name: original_val})}"
            baseline_resp = await self.http.get(baseline_url)

            if baseline_resp.error:
                continue

            # Test with payloads
            for payload in PayloadEngine.get_payloads("sqli"):
                test_val = f"{original_val}{payload}"
                test_url = f"{base}?{urlencode({param_name: test_val})}"
                resp = await self.http.get(test_url)

                if resp.error:
                    continue

                # Check for database errors
                db_type, error_match = self._detect_error(resp.body)

                if db_type:
                    # Validate: ensure error wasn't in baseline
                    baseline_db, _ = self._detect_error(baseline_resp.body)
                    if baseline_db:
                        continue  # Error exists in baseline, not caused by us

                    poc = PayloadEngine.generate_poc("sqli", base, param_name, payload)
                    finding = {
                        "type": f"SQL Injection (Error-based, {db_type})",
                        "severity": "critical",
                        "title": f"SQL Injection in parameter '{param_name}'",
                        "description": (
                            f"Error-based SQL injection detected in parameter '{param_name}'. "
                            f"Database type: {db_type}. The payload '{payload}' triggered a "
                            f"database error in the response."
                        ),
                        "evidence": f"Database: {db_type}\nPayload: {payload}\nError: {error_match}",
                        "request": test_url,
                        "response": resp.body[:2000],
                        "reproduction": poc,
                        "confidence": "high",
                    }
                    findings.append(finding)
                    logger.finding("critical", "SQLi", base,
                                   f"param={param_name}, db={db_type}")
                    break  # One finding per param

            # ── OOB blind SQLi payloads ──
            if self.oob and self.oob.is_registered:
                oob_payloads = self.oob.get_oob_payloads("sqli", base, param_name)
                for oob_payload in oob_payloads:
                    test_url = f"{base}?{urlencode({param_name: original_val + oob_payload})}"
                    await self.http.get(test_url)  # Fire and forget

        return findings

    def _detect_error(self, body: str) -> tuple[str | None, str | None]:
        """Check response body for database error patterns."""
        for db_type, patterns in DB_ERROR_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    return db_type, match.group(0)
        return None, None
