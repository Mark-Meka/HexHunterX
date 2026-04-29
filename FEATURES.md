# HexHunter -- Feature Deep Dive

A detailed breakdown of every feature in HexHunter: how it works, how it was built, and the efficiency techniques behind each component.

---

## Table of Contents

1. [Core Engine & Workflow](#1-core-engine--workflow)
2. [Target Input & Validation](#2-target-input--validation)
3. [Reconnaissance Module](#3-reconnaissance-module)
4. [Scanning Module](#4-scanning-module)
5. [Fuzzing Engine](#5-fuzzing-engine)
6. [Vulnerability Detection](#6-vulnerability-detection)
7. [Smart Decision Engine](#7-smart-decision-engine)
8. [External Tool Integrations](#8-external-tool-integrations)
9. [Database & Persistence](#9-database--persistence)
10. [Reporting System](#10-reporting-system)
11. [Networking Layer](#11-networking-layer)
12. [CLI Interface](#12-cli-interface)
13. [Logging System](#13-logging-system)

---

## 1. Core Engine & Workflow

**Files:** `core/engine.py`, `core/scheduler.py`

### How It Runs

The engine is the brain of HexHunter. When you run `python main.py -t target.com --full-scan`, this happens:

```
CLI Parser --> Config Loader --> Engine.initialize()
                                      |
                                      v
                               Validate Target
                                      |
                                      v
                              Store in Database
                                      |
                                      v
                    Run Phases in Sequence:
                    Recon --> Scanning --> Fuzzing --> Vuln Checks --> Report
                                      |
                                      v
                              Print Summary
```

Each phase calls its corresponding module, collects results, and stores them in SQLite before moving to the next phase. If one phase fails, the engine logs the error and continues to the next.

### How It Was Built

The engine uses Python's `asyncio` as the foundation. The `HexHunterEngine` class manages the lifecycle:

1. **`initialize()`** -- connects to SQLite, creates the HTTP client with connection pooling
2. **`run()`** -- validates the target, then iterates through the requested phases
3. **`shutdown()`** -- closes all connections gracefully

The `TaskScheduler` handles concurrent task execution using `asyncio.Semaphore` to cap the number of simultaneous tasks (default: 50). This prevents resource exhaustion.

### Efficiency

- **Async I/O**: All network operations are non-blocking. While one request waits for a response, others can proceed.
- **Phase skipping**: The `--resume` flag checks the database for existing data. If a phase already has results, it skips it entirely.
- **Semaphore concurrency**: Instead of spawning unlimited coroutines, a semaphore limits concurrent tasks to prevent socket exhaustion and memory bloat.

---

## 2. Target Input & Validation

**File:** `utils/validators.py`

### How It Runs

When you provide `-t target.com`, the `InputValidator` classifies and validates the input:

```
Raw Input --> Classify Type --> Validate --> Normalize --> Return ValidatedTarget
```

Supported input types:
- **Domain**: `example.com` -- validated via regex + tldextract library
- **IP**: `192.168.1.1` -- validated via Python's `ipaddress` module
- **CIDR**: `192.168.1.0/24` -- validated and expanded via `ipaddress.ip_network()`
- **URL**: `https://example.com/path` -- parsed via `urllib.parse`

### How It Was Built

The `InputValidator` uses a chain-of-responsibility pattern:

1. Check if input starts with `http://` or `https://` -- try URL validation
2. Check if input contains `/` and matches CIDR regex -- try CIDR validation
3. Check if input matches IPv4 regex -- try IP validation
4. Fall through to domain validation

The `ScopeManager` class handles in-scope/out-of-scope filtering. It supports wildcard patterns (`*.example.com`) and CIDR ranges. Out-of-scope always takes precedence over in-scope (deny-first logic).

### Efficiency

- **Early classification**: The chain stops at the first successful match, avoiding unnecessary validation attempts.
- **tldextract caching**: The library caches the public suffix list, so repeated domain validations are fast.
- **No DNS calls during validation**: Validation is purely syntactic. DNS resolution happens later during recon.

---

## 3. Reconnaissance Module

**Files:** `modules/recon/subdomains.py`, `modules/recon/hosts.py`, `modules/recon/asn.py`, `modules/recon/endpoints.py`

### 3.1 Subdomain Enumeration

#### How It Runs

Three techniques run in sequence, and results are merged:

```
Passive (crt.sh + HackerTarget APIs)
        |
        v
Active (DNS brute-force with wordlist)
        |
        v
Permutations (prefix/suffix combinations)
        |
        v
Deduplicate + Filter (must end with target domain)
```

**Passive enumeration** queries two free APIs:
- **crt.sh**: Queries Certificate Transparency logs. Every SSL certificate ever issued is logged publicly. We query `https://crt.sh/?q=%25.{domain}&output=json` and extract all `name_value` fields.
- **HackerTarget**: A simple API that returns known subdomains from their database.

**Active brute-force** loads the subdomain wordlist (`data/wordlists/common_subdomains.txt`) and attempts DNS resolution for each candidate (e.g., `dev.example.com`, `api.example.com`). Uses `dnspython` with a 3-second timeout per query.

**Permutations** take discovered subdomains and generate variations. If we found `api.example.com`, we also try `dev-api.example.com`, `api-staging.example.com`, etc.

#### Efficiency

- **Concurrent DNS queries**: Up to 50 simultaneous DNS lookups via `asyncio.Semaphore`.
- **Wordlist limiting**: Only the first 500 entries are used for brute-force to balance coverage vs. speed.
- **Set-based deduplication**: All results go into a Python `set`, automatically removing duplicates.
- **Domain filtering**: Only subdomains ending with the target domain are kept, rejecting noise.

### 3.2 Live Host Detection

#### How It Runs

```
For each subdomain:
    1. Resolve IP via DNS
    2. Try HTTPS request
    3. If HTTPS fails, try HTTP
    4. Extract: status code, page title, IP
    5. Mark as alive/dead in database
```

#### Efficiency

- **HTTPS-first**: Most modern sites use HTTPS. Trying it first avoids an unnecessary HTTP roundtrip.
- **Concurrent probing**: 30 simultaneous probes via semaphore.
- **Lightweight requests**: Only needs the first response, not full page content.

### 3.3 Endpoint Collection

#### How It Runs

Three sources are combined:

1. **HTML Crawling**: Fetches the page, parses with BeautifulSoup, extracts all `href`, `src`, and `action` attributes from `<a>`, `<link>`, `<script>`, `<form>`, `<iframe>` tags.

2. **JavaScript Parsing**: Finds all `<script>` tags (both inline and external). Applies regex patterns to extract URLs from common patterns like `fetch('/api/...')`, `axios.get('/endpoint')`, `url: '/path'`.

3. **Wayback Machine**: Queries `web.archive.org/cdx/search/cdx` for historical URLs. This finds endpoints that may still work but are no longer linked from the live site.

#### Efficiency

- **Static asset filtering**: Ignores `.png`, `.jpg`, `.css`, `.woff`, etc. -- these aren't interesting for security testing.
- **External domain filtering**: Only keeps URLs belonging to the target domain.
- **JS file limiting**: Only processes the first 10 external JS files to avoid analysis paralysis on large sites.

---

## 4. Scanning Module

**Files:** `modules/scanning/ports.py`, `modules/scanning/services.py`, `modules/scanning/directories.py`, `modules/scanning/fingerprint.py`

### 4.1 Port Scanning

#### How It Runs

```
For each target IP:
    For each port in TOP_PORTS (35 ports):
        1. Attempt async TCP connect
        2. If connected --> port is open
        3. Try to read banner (first 1024 bytes)
        4. Map port to known service name
```

Uses `asyncio.open_connection()` for non-blocking TCP connections with a 2-second timeout.

#### Efficiency

- **Async sockets**: 100 simultaneous port checks via semaphore. A 35-port scan completes in ~2 seconds.
- **Known service mapping**: A dictionary maps port numbers to service names (e.g., 22=ssh, 80=http) without needing banner analysis for common ports.
- **Timeout-based filtering**: Closed/filtered ports timeout quickly (2s), so they don't block the scan.

### 4.2 Directory Brute-Force

#### How It Runs

```
1. Load wordlist (common_dirs.txt, ~130 entries)
2. Generate URL list: base_url + word + extension (.php, .html, .js, etc.)
3. Get baseline 404 response (request a known-nonexistent path)
4. Test each URL concurrently
5. Filter results:
   - Remove 404 status codes
   - Remove responses matching baseline 404 (custom error pages)
   - Remove false positives (50%+ same response size = custom 404)
```

#### Efficiency

- **Baseline 404 detection**: Many servers return 200 OK for everything with a custom "not found" page. HexHunter requests a garbage path first and uses its response size as a baseline to filter these out.
- **Smart deduplication**: If more than 50% of results share the same response size, they're likely all the same custom 404 page and are discarded.
- **Concurrent with semaphore**: 30 simultaneous requests.

### 4.3 Technology Fingerprinting

#### How It Runs

```
1. Send GET request to target
2. Check response headers against rules:
   - Server: nginx/1.x --> "Nginx"
   - X-Powered-By: PHP --> "PHP"
   - Set-Cookie: PHPSESSID --> "PHP"
3. Check response body against rules:
   - wp-content/ --> "WordPress"
   - __next --> "Next.js"
   - data-reactroot --> "React"
```

#### Efficiency

- **Single request**: Only one HTTP request needed per host. All detection is done via pattern matching on headers and body.
- **Regex-based**: Compiled regex patterns are fast for string matching.
- **Cookie analysis**: Session cookie names reveal technologies without any extra requests (PHPSESSID=PHP, JSESSIONID=Java, etc.).

---

## 5. Fuzzing Engine

**Files:** `modules/fuzzing/params.py`, `modules/fuzzing/endpoints.py`, `modules/fuzzing/wordlists.py`, `modules/fuzzing/payloads.py`

### 5.1 Parameter Discovery

#### How It Runs

```
1. Load parameter wordlist (common_params.txt, ~150 names)
2. Get baseline response for the URL
3. For each parameter name:
   a. Inject a unique canary value: ?param_name=hxh7r3fpar
   b. Send request
   c. Check if canary is reflected in response body
   d. Check if response size differs significantly from baseline
   e. Check if status code changed
4. If any check triggers --> parameter exists
```

The canary (`hxh7r3f` + first 4 chars of param name) is unique enough to not appear naturally in responses.

#### Efficiency

- **Batch processing**: Tests 50 parameters at a time.
- **Three detection methods**: Reflection, size change, and status change catch different types of parameters.
- **Limited to 200 params**: Prevents excessive scanning on a single URL.

### 5.2 Hidden Endpoint Discovery

#### How It Runs

Checks a curated list of common sensitive paths:

```
/api, /api/v1, /graphql, /swagger, /swagger.json
/.env, /.git/HEAD, /robots.txt, /sitemap.xml
/admin, /console, /dashboard
/debug, /trace, /metrics, /health
/wp-admin, /wp-login.php
/backup, /backup.sql, /backup.zip
```

Then checks for backup files of discovered endpoints (appending `.bak`, `.old`, `.swp`, etc.).

#### Efficiency

- **Curated list**: Only ~35 high-value paths, not thousands. Each represents a common misconfiguration or sensitive endpoint.
- **Baseline filtering**: Uses the same 404 baseline technique as directory brute-force.

### 5.3 Payload Engine

#### How It Runs

The `PayloadEngine` is a static utility that provides:

1. **Categorized payloads**: XSS, SQLi, redirect, IDOR, SSTI -- each with purpose-built payload lists.
2. **Encoding**: URL encoding, double URL encoding, base64, HTML encoding.
3. **PoC generation**: Creates formatted Proof-of-Concept markdown with reproduction steps.

Other modules call `PayloadEngine.get_payloads("xss")` to get the appropriate payloads for their detection type.

---

## 6. Vulnerability Detection

**Files:** `modules/vulns/xss.py`, `modules/vulns/sqli.py`, `modules/vulns/redirect.py`, `modules/vulns/idor.py`, `modules/vulns/misconfig.py`

### 6.1 XSS Detection (Reflected + DOM)

#### How It Runs

**Reflected XSS:**
```
1. For each parameter in the URL:
   a. Inject canary: ?param=hxhx5sparamname
   b. Check if canary appears in response body
   c. If reflected --> determine context:
      - html_body: canary is in plain HTML
      - html_attr: canary is inside an attribute value
      - script: canary is inside <script> tags
      - comment: canary is inside HTML comments
   d. Select context-appropriate payloads
   e. Test payloads (max 5 per parameter)
   f. Verify: check if dangerous characters (<script, onerror=, etc.) survived in response
```

**DOM XSS:**
```
1. Fetch page source
2. Search for DOM sources: document.URL, location.hash, document.referrer, etc.
3. Search for DOM sinks: innerHTML=, eval(), document.write(), etc.
4. If both sources AND sinks found --> potential DOM XSS
```

#### Efficiency

- **Context-aware payloads**: Instead of trying all payloads blindly, the context analysis selects only payloads that would work in that specific reflection point. HTML attribute context gets `" onmouseover="alert(1)"`, script context gets `';alert(1);//`.
- **Canary-first approach**: Only parameters that reflect input are tested further. This eliminates 80%+ of parameters immediately.
- **5 payload limit per param**: Prevents excessive requests while still testing key vectors.
- **False positive reduction**: Verifies that the actual dangerous characters (not just the canary) survived in the response.

### 6.2 SQL Injection Detection

#### How It Runs

```
1. For each parameter:
   a. Get baseline response (normal value)
   b. Append SQL payloads to the normal value
   c. Check response body for database error patterns:
      - MySQL: "SQL syntax.*MySQL", "Warning.*mysqli_"
      - PostgreSQL: "PostgreSQL.*ERROR", "Warning.*pg_"
      - MSSQL: "SQL Server.*Driver", "OLE DB.*SQL Server"
      - Oracle: "ORA-\d{5}"
      - SQLite: "SQLite.Exception", "SQLITE_ERROR"
   d. If error found AND error wasn't in baseline --> confirmed SQLi
```

#### Efficiency

- **Baseline comparison**: Critical for false positive reduction. If the baseline response already contains database errors (e.g., a debug page), those aren't counted as findings.
- **Multi-database support**: 5 database engines covered with 30+ error patterns total.
- **Error-based only**: Time-based and boolean-based detection are suggested in the PoC but not automated, keeping the scan fast.

### 6.3 Open Redirect Detection

#### How It Runs

```
1. Identify redirect parameters (from URL or common names like url, redirect, next, goto)
2. For each parameter:
   a. Inject external domain: https://evil.hexhunter.test
   b. Send request WITHOUT following redirects
   c. Check if response is 301/302/307/308
   d. Check Location header for external domain
   e. Also check body for meta refresh / JS redirects
```

#### Efficiency

- **No redirect following**: Sends with `allow_redirects=False`. This is crucial -- following the redirect would actually navigate to the evil domain.
- **Multiple payload formats**: Tests `https://`, `//`, `/\`, `///` variants to bypass common filters.
- **Server + client-side**: Checks both HTTP Location header redirects and JavaScript/meta-refresh redirects.

### 6.4 IDOR Detection

#### How It Runs

```
1. Identify parameters containing numeric IDs (id, user_id, account, etc.)
2. Get baseline response with original ID
3. Test adjacent IDs: id-1, id+1, id+100
4. Compare responses:
   - Both must return 200
   - Bodies must differ (different objects)
   - Size ratio must be reasonable (0.3x - 3.0x)
5. Also scan URL paths for patterns like /users/123
```

#### Efficiency

- **Pattern-based detection**: Only tests parameters whose names match known ID patterns.
- **Response comparison**: Uses multiple signals (status, body content, size ratio) to reduce false positives.
- **Path analysis**: Detects `/resource/123` patterns without making any requests.

### 6.5 Misconfiguration Detection

#### How It Runs

**CORS Check:**
```
1. Send request with Origin: https://evil.hexhunter.test
2. Check Access-Control-Allow-Origin header:
   - Reflects evil origin + Allow-Credentials: true --> CRITICAL
   - Reflects evil origin without credentials --> MEDIUM
   - Wildcard (*) --> LOW
3. Also test with Origin: null (sandboxed iframe bypass)
```

**Security Headers:**
```
Check for missing:
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options (clickjacking)
- X-Content-Type-Options (MIME sniffing)
- Referrer-Policy
- Permissions-Policy
```

**Information Disclosure:**
```
Check for revealing headers:
- Server: Apache/2.4.41
- X-Powered-By: PHP/8.1
- X-AspNet-Version
- X-Debug-Token
```

#### Efficiency

- **Single request for headers**: One GET request reveals all header-based issues.
- **CORS needs one extra request**: Only one additional request with a forged Origin header.
- **No false positives**: Header checks are binary -- the header is either present or not.

---

## 7. Smart Decision Engine

**File:** `core/decision.py`

### How It Runs

After the scanning phase completes, the decision engine analyzes all collected data:

```
Endpoints + Technologies + Scan Results
                |
                v
        Build TargetProfile:
        - has_login? (regex for /login, /signin, type="password")
        - has_api? (regex for /api/, /graphql, application/json)
        - has_admin_panel? (regex for /admin, /dashboard, /panel)
        - has_file_upload? (regex for type="file", multipart/form-data)
        - param_count (total parameters across all endpoints)
        - CMS detection (WordPress, Joomla, Drupal, Magento)
        - Server detection (Nginx, Apache, IIS)
                |
                v
        Calculate Priority Score (0-100):
        - Login: +25
        - API: +20
        - Admin panel: +20
        - File upload: +15
        - High param count: +5 to +10
        - CMS detected: +10
                |
                v
        Generate Recommendations:
        - "LOGIN_DETECTED: Prioritize authentication testing"
        - "API_DETECTED: Enable API-specific fuzzing"
        - "HIGH_PARAMS: Increase fuzzing depth"
```

The profile is then used to adjust:
- **Fuzzing depth**: More parameters = deeper fuzzing
- **Vulnerability checks**: API targets get IDOR checks prioritized
- **Authentication testing**: Login pages get auth bypass checks

### Efficiency

- **Zero extra requests**: Analyzes data already collected. No additional network traffic.
- **Regex-based matching**: Fast pattern matching against stored responses.
- **Actionable output**: Each recommendation maps directly to a configuration change in subsequent phases.

---

## 8. External Tool Integrations

**Files:** `integrations/base.py`, `integrations/subfinder.py`, `integrations/httpx.py`, `integrations/ffuf.py`, `integrations/nuclei.py`

### How It Runs

Each integration follows the same pattern (abstract base class):

```
1. Check if tool is installed (shutil.which)
2. Build CLI command with arguments
3. Execute via asyncio.create_subprocess_exec
4. Capture stdout/stderr
5. Parse output (JSON/JSONL) into unified schema
```

If a tool isn't installed, HexHunter logs a warning and falls back to its built-in Python implementation.

### How It Was Built

The `BaseToolWrapper` abstract class enforces a consistent interface:
- `tool_name` -- binary name to look for on PATH
- `build_command(**kwargs)` -- construct CLI arguments
- `parse_output(stdout)` -- transform tool output into HexHunter's format

Each wrapper is ~40 lines of code because all the execution logic lives in the base class.

### Efficiency

- **Graceful degradation**: Missing tools don't break the scan. Built-in alternatives are used automatically.
- **Timeout protection**: Each tool execution has a 300-second timeout. If a tool hangs, it's killed.
- **JSON output**: All tools are invoked with JSON output flags for reliable parsing.

---

## 9. Database & Persistence

**Files:** `database/manager.py`, `database/models.py`, `database/schema.sql`

### How It Runs

SQLite database with 6 tables:

| Table | Purpose | Key Fields |
|-------|---------|------------|
| `targets` | Root targets | domain, ip, cidr, scope |
| `subdomains` | Discovered subdomains | name, ip, status_code, is_alive |
| `endpoints` | URLs found | url, method, parameters |
| `scan_results` | Port/service data | port, service, banner |
| `vulnerabilities` | Findings | type, severity, evidence, request, response |
| `logs` | Activity log | module, message, timestamp |

### How It Was Built

Uses `aiosqlite` for non-blocking database operations. The `DatabaseManager` class provides:
- **CRUD operations** for all tables
- **Bulk insert** for subdomains (avoids individual INSERT overhead)
- **Resume support**: `has_phase_data()` checks if a phase already has data
- **Statistics**: `get_stats()` returns counts and severity breakdowns
- **Deduplication**: UNIQUE constraints on tables prevent duplicate entries

### Efficiency

- **WAL mode**: `PRAGMA journal_mode=WAL` enables concurrent reads while writing.
- **INSERT OR IGNORE**: Duplicate entries are silently skipped instead of raising errors.
- **Indexed queries**: Indexes on `target_id`, `severity`, and `vuln_type` speed up reporting queries.
- **Async operations**: Database I/O doesn't block network operations.

---

## 10. Reporting System

**Files:** `reports/generator.py`, `reports/templates/report.html`

### How It Runs

```
1. Gather all data from database:
   - Target info, subdomains, endpoints, scan results, vulnerabilities
   - Calculate severity counts
2. Generate JSON report (raw structured data)
3. Generate HTML report (Jinja2 template rendering)
```

### HTML Report Features

- **Dark theme** with CSS custom properties (variables)
- **Summary cards** showing key metrics at a glance
- **Severity bar** with color-coded counts (critical=red, high=orange, medium=yellow, low=green)
- **Vulnerability cards** with collapsible evidence sections
- **Data tables** for subdomains and open ports
- **Gradient text** header using `background-clip: text`
- **Click-to-expand** evidence and reproduction steps

### Efficiency

- **Single database query pass**: All data is gathered in one batch, not per-vulnerability.
- **Jinja2 templates**: Server-side rendering produces a static HTML file. No JavaScript frameworks needed.
- **Body truncation**: Response bodies in evidence are capped at 5000 characters to keep file size manageable.

---

## 11. Networking Layer

**File:** `utils/network.py`

### How It Runs

The `AsyncHTTPClient` wraps `aiohttp` with production features:

```
Request flow:
    Acquire rate limiter token
        |
        v
    Send request via aiohttp session
        |
        v
    Success? --> Return HTTPResponse
        |
    Failure? --> Retry with exponential backoff (2^attempt seconds)
        |
        v
    Max retries hit? --> Return error response
```

### Key Components

**Rate Limiter (Token Bucket):**
```
- Bucket starts full (e.g., 10 tokens)
- Each request consumes 1 token
- Tokens refill at configured rate (e.g., 10/second)
- If bucket is empty, request waits until token available
```

**Connection Pooling:**
- `aiohttp.TCPConnector(limit=100)` maintains up to 100 persistent TCP connections
- Connections are reused across requests to the same host

**Evidence Capture:**
- Every request/response is stored as `HTTPRequest`/`HTTPResponse` dataclasses
- Includes: URL, method, headers, body, status code, elapsed time, redirect chain

### Efficiency

- **Connection reuse**: TCP handshake and TLS negotiation happen once per host, not per request.
- **Token bucket rate limiting**: Smooth request distribution (no bursts) prevents WAF triggers.
- **Exponential backoff**: Failed requests wait 1s, 2s, 4s before retrying, giving servers time to recover.
- **SSL verification disabled by default**: Avoids failures on self-signed certs (common in security testing).

---

## 12. CLI Interface

**File:** `cli/interface.py`

### How It Runs

Uses Python's `argparse` with grouped arguments:

```
Scan Phases:     --recon, --scan, --fuzz, --vuln, --full-scan
Configuration:   --config, --threads, --rate-limit, --timeout
Output:          --output, --format, --silent
Advanced:        --resume, --db, --scope-file, --exclude-file
```

The parser returns a flat dictionary that the engine consumes. CLI arguments override config file values.

### Efficiency

- **Phase composition**: Users can run any combination of phases without running unnecessary ones.
- **Config override**: CLI flags take precedence over YAML config, allowing quick adjustments without editing files.
- **Auto-report**: The report phase is automatically appended when any scan phase is selected.

---

## 13. Logging System

**File:** `utils/logger.py`

### How It Runs

Dual-output logging:

1. **Console**: Rich library with color-coded output, progress bars, and severity badges
2. **File**: Plain text with timestamps, written to `logs/hexhunter_YYYYMMDD.log`

Special log methods:
- `logger.phase("RECON")` -- prints a visual phase separator
- `logger.finding("critical", "SQLi", url, detail)` -- prints a color-coded vulnerability finding
- `logger.progress(50, 100, "scanning")` -- prints an inline progress bar

### Efficiency

- **Singleton pattern**: `HexHunterLogger.get_logger("module")` returns cached instances. Creating a logger for "recon.subdomains" twice returns the same object.
- **Level filtering**: Console shows INFO+, file captures DEBUG+. Verbose debug output doesn't clutter the terminal.
- **Lazy formatting**: Log messages only format if the level is enabled.

---

## Performance Summary

| Feature | Concurrency | Rate Limit | Key Optimization |
|---------|------------|------------|------------------|
| Subdomain brute-force | 50 concurrent DNS | N/A | Set deduplication |
| Host probing | 30 concurrent | Token bucket | HTTPS-first |
| Port scanning | 100 concurrent | N/A | 2s timeout |
| Directory brute-force | 30 concurrent | Token bucket | Baseline 404 filtering |
| Parameter discovery | 20 concurrent | Token bucket | Canary reflection |
| Vulnerability checks | Sequential per host | Token bucket | Context-aware payloads |
| Database writes | Async non-blocking | N/A | WAL mode + indexes |
| External tools | 1 process each | Tool's own | JSON output parsing |

---

## Design Principles

1. **Async-first**: Every network operation uses `asyncio`. No blocking I/O anywhere in the scan pipeline.

2. **Evidence-first**: Every finding stores the full request URL and response data. This makes report verification straightforward and mimics real bug bounty methodology.

3. **False positive reduction**: Every detector uses at least one validation technique (baseline comparison, context analysis, or multi-signal confirmation).

4. **Graceful degradation**: External tools are optional. Missing dependencies don't crash the framework.

5. **Modular design**: Each module is independent. You can import and use `XSSDetector` or `PortScanner` standalone without the rest of the framework.

6. **Scan resume**: Database-backed state means interrupted scans can resume from the last completed phase, avoiding redundant work on large targets.
