"""
HexHunterX -- Database Manager.

Async SQLite database handler with full CRUD and scan resume support.
"""

import json
from pathlib import Path

import aiosqlite

from database.models import (
    Target, Subdomain, Endpoint, ScanResult, Vulnerability, LogEntry
)
from utils.logger import HexHunterXLogger

logger = HexHunterXLogger.get_logger("database")

SCHEMA_PATH = Path(__file__).parent / "schema.sql"


class DatabaseManager:
    """
    Async database handler for HexHunterX.

    Supports insert, update, query, and scan resume from SQLite.
    """

    def __init__(self, db_path: str = "HexHunterX.db"):
        self.db_path = db_path
        self._db: aiosqlite.Connection | None = None

    async def connect(self):
        """Connect to database and initialize schema."""
        self._db = await aiosqlite.connect(self.db_path)
        self._db.row_factory = aiosqlite.Row
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA foreign_keys=ON")
        await self._init_schema()
        logger.info(f"Database connected: {self.db_path}")

    async def close(self):
        if self._db:
            await self._db.close()

    async def _init_schema(self):
        """Initialize database tables from schema.sql."""
        schema = SCHEMA_PATH.read_text(encoding="utf-8")
        await self._db.executescript(schema)
        await self._db.commit()

    # ── Target CRUD ─────────────────────────────────
    async def insert_target(self, target: Target) -> int:
        cursor = await self._db.execute(
            "INSERT OR IGNORE INTO targets (domain, ip, cidr, scope, target_type) VALUES (?, ?, ?, ?, ?)",
            (target.domain, target.ip, target.cidr, target.scope, target.target_type))
        await self._db.commit()
        if cursor.lastrowid:
            return cursor.lastrowid
        # If IGNORE hit, fetch existing
        row = await self._db.execute_fetchall(
            "SELECT id FROM targets WHERE domain IS ? AND ip IS ? AND cidr IS ?",
            (target.domain, target.ip, target.cidr))
        return row[0][0] if row else 0

    async def get_target(self, target_id: int) -> dict | None:
        async with self._db.execute("SELECT * FROM targets WHERE id = ?", (target_id,)) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None

    async def get_all_targets(self) -> list[dict]:
        async with self._db.execute("SELECT * FROM targets") as cur:
            return [dict(r) for r in await cur.fetchall()]

    # ── Subdomain CRUD ──────────────────────────────
    async def insert_subdomain(self, sub: Subdomain) -> int:
        cursor = await self._db.execute(
            "INSERT OR IGNORE INTO subdomains (target_id, name, ip, status_code, title, tech, source, is_alive) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (sub.target_id, sub.name, sub.ip, sub.status_code, sub.title, sub.tech, sub.source, int(sub.is_alive)))
        await self._db.commit()
        if cursor.lastrowid:
            return cursor.lastrowid
        row = await self._db.execute_fetchall(
            "SELECT id FROM subdomains WHERE target_id = ? AND name = ?",
            (sub.target_id, sub.name))
        return row[0][0] if row else 0

    async def insert_subdomains_bulk(self, subs: list[Subdomain]) -> int:
        """Bulk insert subdomains. Returns count of inserted rows."""
        count = 0
        for sub in subs:
            result = await self.insert_subdomain(sub)
            if result:
                count += 1
        return count

    async def get_subdomains(self, target_id: int, alive_only: bool = False) -> list[dict]:
        query = "SELECT * FROM subdomains WHERE target_id = ?"
        if alive_only:
            query += " AND is_alive = 1"
        async with self._db.execute(query, (target_id,)) as cur:
            return [dict(r) for r in await cur.fetchall()]

    async def update_subdomain(self, sub_id: int, **kwargs):
        if not kwargs:
            return  # Nothing to update
        sets = ", ".join(f"{k} = ?" for k in kwargs)
        vals = list(kwargs.values()) + [sub_id]
        await self._db.execute(f"UPDATE subdomains SET {sets} WHERE id = ?", vals)
        await self._db.commit()

    # ── Endpoint CRUD ───────────────────────────────
    async def insert_endpoint(self, ep: Endpoint) -> int:
        cursor = await self._db.execute(
            "INSERT OR IGNORE INTO endpoints (subdomain_id, url, method, parameters, content_type, status_code, content_length, source) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (ep.subdomain_id, ep.url, ep.method, ep.parameters, ep.content_type,
             ep.status_code, ep.content_length, ep.source))
        await self._db.commit()
        if cursor.lastrowid:
            return cursor.lastrowid
        row = await self._db.execute_fetchall(
            "SELECT id FROM endpoints WHERE subdomain_id = ? AND url = ? AND method = ?",
            (ep.subdomain_id, ep.url, ep.method))
        return row[0][0] if row else 0

    async def get_endpoints(self, subdomain_id: int) -> list[dict]:
        async with self._db.execute(
            "SELECT * FROM endpoints WHERE subdomain_id = ?", (subdomain_id,)) as cur:
            return [dict(r) for r in await cur.fetchall()]

    async def get_all_endpoints_for_target(self, target_id: int) -> list[dict]:
        query = """
            SELECT e.* FROM endpoints e
            JOIN subdomains s ON e.subdomain_id = s.id
            WHERE s.target_id = ?
        """
        async with self._db.execute(query, (target_id,)) as cur:
            return [dict(r) for r in await cur.fetchall()]

    # ── Scan Results CRUD ───────────────────────────
    async def insert_scan_result(self, sr: ScanResult) -> int:
        cursor = await self._db.execute(
            "INSERT INTO scan_results (target_id, subdomain_id, port, protocol, service, version, banner, state) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (sr.target_id, sr.subdomain_id, sr.port, sr.protocol,
             sr.service, sr.version, sr.banner, sr.state))
        await self._db.commit()
        return cursor.lastrowid

    async def get_scan_results(self, target_id: int) -> list[dict]:
        async with self._db.execute(
            "SELECT * FROM scan_results WHERE target_id = ?", (target_id,)) as cur:
            return [dict(r) for r in await cur.fetchall()]

    # ── Vulnerability CRUD ──────────────────────────
    async def insert_vulnerability(self, vuln: Vulnerability) -> int:
        cursor = await self._db.execute(
            "INSERT INTO vulnerabilities (endpoint_id, subdomain_id, target_id, vuln_type, severity, title, "
            "description, evidence, request_data, response_data, reproduction, confidence, is_verified) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (vuln.endpoint_id, vuln.subdomain_id, vuln.target_id, vuln.vuln_type,
             vuln.severity, vuln.title, vuln.description, vuln.evidence,
             vuln.request_data, vuln.response_data, vuln.reproduction,
             vuln.confidence, int(vuln.is_verified)))
        await self._db.commit()
        return cursor.lastrowid

    async def get_vulnerabilities(self, target_id: int = None, severity: str = None) -> list[dict]:
        query = "SELECT * FROM vulnerabilities WHERE 1=1"
        params = []
        if target_id:
            query += " AND target_id = ?"
            params.append(target_id)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        query += " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"
        async with self._db.execute(query, params) as cur:
            return [dict(r) for r in await cur.fetchall()]

    # ── Logging ─────────────────────────────────────
    async def insert_log(self, module: str, message: str, level: str = "INFO"):
        await self._db.execute(
            "INSERT INTO logs (module, level, message) VALUES (?, ?, ?)",
            (module, level, message))
        await self._db.commit()

    # ── Statistics ──────────────────────────────────
    async def get_stats(self, target_id: int) -> dict:
        """Get scan statistics for a target."""
        stats = {}
        for table in ["subdomains", "endpoints", "scan_results", "vulnerabilities"]:
            col = "target_id" if table != "endpoints" else "subdomain_id"
            if table == "endpoints":
                query = f"SELECT COUNT(*) FROM endpoints e JOIN subdomains s ON e.subdomain_id = s.id WHERE s.target_id = ?"
            else:
                query = f"SELECT COUNT(*) FROM {table} WHERE target_id = ?"
            async with self._db.execute(query, (target_id,)) as cur:
                row = await cur.fetchone()
                stats[table] = row[0]

        # Vuln severity breakdown
        async with self._db.execute(
            "SELECT severity, COUNT(*) FROM vulnerabilities WHERE target_id = ? GROUP BY severity",
            (target_id,)) as cur:
            stats["vuln_breakdown"] = {r[0]: r[1] for r in await cur.fetchall()}

        return stats

    # ── Resume Support ──────────────────────────────
    async def has_phase_data(self, target_id: int, phase: str) -> bool:
        """Check if a scan phase has existing data (for resume support)."""
        checks = {
            "recon": "SELECT COUNT(*) FROM subdomains WHERE target_id = ?",
            "scanning": "SELECT COUNT(*) FROM scan_results WHERE target_id = ?",
            "fuzzing": "SELECT COUNT(*) FROM endpoints e JOIN subdomains s ON e.subdomain_id = s.id WHERE s.target_id = ? AND e.source = 'fuzzing'",
            "vulns": "SELECT COUNT(*) FROM vulnerabilities WHERE target_id = ?",
        }
        query = checks.get(phase)
        if not query:
            return False
        async with self._db.execute(query, (target_id,)) as cur:
            row = await cur.fetchone()
            return row[0] > 0 if row else False
