"""
HexHunterX -- Database Models.

Dataclass-based models mapping to SQLite tables.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Target:
    domain: str | None = None
    ip: str | None = None
    cidr: str | None = None
    scope: str = "in-scope"
    target_type: str = "domain"
    id: int | None = None
    created_at: str | None = None
    updated_at: str | None = None


@dataclass
class Subdomain:
    target_id: int = 0
    name: str = ""
    ip: str | None = None
    status_code: int | None = None
    title: str | None = None
    tech: str | None = None
    source: str | None = None
    is_alive: bool = False
    id: int | None = None
    created_at: str | None = None


@dataclass
class Endpoint:
    subdomain_id: int = 0
    url: str = ""
    method: str = "GET"
    parameters: str | None = None
    content_type: str | None = None
    status_code: int | None = None
    content_length: int | None = None
    source: str | None = None
    id: int | None = None
    created_at: str | None = None


@dataclass
class ScanResult:
    target_id: int = 0
    subdomain_id: int | None = None
    port: int = 0
    protocol: str = "tcp"
    service: str | None = None
    version: str | None = None
    banner: str | None = None
    state: str = "open"
    id: int | None = None
    created_at: str | None = None


@dataclass
class Vulnerability:
    vuln_type: str = ""
    severity: str = "info"
    endpoint_id: int | None = None
    subdomain_id: int | None = None
    target_id: int | None = None
    title: str | None = None
    description: str | None = None
    evidence: str | None = None
    request_data: str | None = None
    response_data: str | None = None
    reproduction: str | None = None
    confidence: str = "medium"
    is_verified: bool = False
    verification_method: str | None = None
    # AI-ENHANCED
    ai_triage: str | None = None
    id: int | None = None
    created_at: str | None = None


@dataclass
class LogEntry:
    module: str = ""
    level: str = "INFO"
    message: str = ""
    id: int | None = None
    timestamp: str | None = None
