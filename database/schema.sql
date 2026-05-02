-- HexHunterX SQLite Schema
-- Persistent storage for scan state, findings, and evidence.

CREATE TABLE IF NOT EXISTS targets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain      TEXT,
    ip          TEXT,
    cidr        TEXT,
    scope       TEXT DEFAULT 'in-scope',
    target_type TEXT NOT NULL,
    created_at  TEXT DEFAULT (datetime('now')),
    updated_at  TEXT DEFAULT (datetime('now')),
    UNIQUE(domain, ip, cidr)
);

CREATE TABLE IF NOT EXISTS subdomains (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER NOT NULL,
    name        TEXT NOT NULL,
    ip          TEXT,
    status_code INTEGER,
    title       TEXT,
    tech        TEXT,
    source      TEXT,
    is_alive    INTEGER DEFAULT 0,
    created_at  TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (target_id) REFERENCES targets(id),
    UNIQUE(target_id, name)
);

CREATE TABLE IF NOT EXISTS endpoints (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    subdomain_id    INTEGER NOT NULL,
    url             TEXT NOT NULL,
    method          TEXT DEFAULT 'GET',
    parameters      TEXT,
    content_type    TEXT,
    status_code     INTEGER,
    content_length  INTEGER,
    source          TEXT,
    created_at      TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (subdomain_id) REFERENCES subdomains(id),
    UNIQUE(subdomain_id, url, method)
);

CREATE TABLE IF NOT EXISTS scan_results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER NOT NULL,
    subdomain_id INTEGER,
    port        INTEGER,
    protocol    TEXT DEFAULT 'tcp',
    service     TEXT,
    version     TEXT,
    banner      TEXT,
    state       TEXT DEFAULT 'open',
    created_at  TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (target_id) REFERENCES targets(id),
    FOREIGN KEY (subdomain_id) REFERENCES subdomains(id)
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_id     INTEGER,
    subdomain_id    INTEGER,
    target_id       INTEGER,
    vuln_type       TEXT NOT NULL,
    severity        TEXT NOT NULL,
    title           TEXT,
    description     TEXT,
    evidence        TEXT,
    request_data    TEXT,
    response_data   TEXT,
    reproduction    TEXT,
    confidence      TEXT DEFAULT 'medium',
    is_verified     INTEGER DEFAULT 0,
    verification_method TEXT,
    ai_triage       TEXT,
    created_at      TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id),
    FOREIGN KEY (subdomain_id) REFERENCES subdomains(id),
    FOREIGN KEY (target_id) REFERENCES targets(id)
);

CREATE TABLE IF NOT EXISTS logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    module      TEXT NOT NULL,
    level       TEXT DEFAULT 'INFO',
    message     TEXT,
    timestamp   TEXT DEFAULT (datetime('now'))
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_subdomains_target ON subdomains(target_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_subdomain ON endpoints(subdomain_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulns_type ON vulnerabilities(vuln_type);
CREATE INDEX IF NOT EXISTS idx_scan_target ON scan_results(target_id);
