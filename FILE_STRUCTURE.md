# HexHunter -- File Structure & Architecture Guide

> A complete breakdown of every file and folder in the HexHunter penetration testing framework, explaining **what** each component does and **how** it works under the hood.

---

## 📁 Project Root

```
HexHunter/
├── main.py                  ← Entry point (CLI launcher)
├── setup.py                 ← Package installer
├── requirements.txt         ← Python dependencies
├── .gitignore               ← Git exclusion rules
├── README.md                ← Project overview & usage
├── FEATURES.md              ← Deep-dive feature documentation
├── FILE_STRUCTURE.md        ← This file
├── cli/                     ← Command-line interface
├── config/                  ← YAML configuration files
├── core/                    ← Execution engine & orchestration
├── data/                    ← Wordlists & static data
├── database/                ← SQLite persistence layer
├── integrations/            ← External tool wrappers
├── logs/                    ← Runtime log output
├── modules/                 ← All scanning & detection logic
│   ├── recon/               ← Reconnaissance phase
│   ├── scanning/            ← Active scanning phase
│   ├── fuzzing/             ← Fuzzing & payload injection
│   └── vulns/               ← Vulnerability detectors
├── reports/                 ← Report generation & templates
└── utils/                   ← Shared utilities & helpers
```

---

## 🏠 Root Files

### `main.py`
**What:** The application entry point. Parses command-line arguments and launches the scan pipeline.  
**How:** Uses `argparse` to accept target, phases to run (`--recon`, `--scan`, `--fuzz`, `--vuln`, `--report`), concurrency settings, and output preferences. Loads the YAML config, constructs a `HexHunterEngine`, and calls `engine.run()` inside `asyncio.run()`.

### `setup.py`
**What:** Package installation script for `pip install -e .` (editable install).  
**How:** Declares the project metadata (name, version, author) and lists dependencies from `requirements.txt` so the project can be installed as a system-wide command.

### `requirements.txt`
**What:** Pinned Python dependencies.  
**How:** Lists every library the project needs: `aiohttp` (async HTTP), `aiosqlite` (async database), `pyyaml` (config parsing), `rich` (terminal UI), `jinja2` (HTML reports), `dnspython` (DNS lookups), and more. Install via `pip install -r requirements.txt`.

### `.gitignore`
**What:** Tells Git which files to exclude from version control.  
**How:** Ignores `__pycache__/`, `.db` files, `logs/`, IDE configs, and the virtual environment folder.

### `README.md`
**What:** Project overview for GitHub -- features, installation, usage examples.

### `FEATURES.md`
**What:** In-depth technical documentation of every feature, its execution flow, and efficiency optimizations.

---

## 📂 `cli/` -- Command-Line Interface

### `cli/__init__.py`
**What:** Package marker for the CLI module.

### `cli/interface.py`
**What:** Rich terminal UI -- banners, progress bars, interactive prompts.  
**How:** Uses the `rich` library to render a styled ASCII banner, animated scan progress indicators, and formatted result tables. Called by `main.py` to display the startup splash and real-time scan status.

---

## 📂 `config/` -- Configuration

### `config/default.yaml`
**What:** Default settings for every configurable aspect of HexHunter.  
**How:** YAML file loaded at startup. Controls:
- **`general`** -- threads (50), rate limit (10 req/s), timeout (10s), user-agent string
- **`recon`** -- wordlist paths, passive source toggles
- **`scanning`** -- port lists, directory brute-force depth
- **`fuzzing`** -- payload encoding modes, parameter wordlist path
- **`reporting`** -- output directory, formats (JSON/HTML)

The engine reads this at initialization and passes relevant sections to each module.

---

## 📂 `core/` -- Execution Engine

> The brain of HexHunter. Orchestrates the entire scan pipeline.

### `core/__init__.py`
**What:** Package marker.

### `core/engine.py`
**What:** The main orchestrator -- runs the 5-phase pipeline: Recon → Scanning → Fuzzing → Vulnerability Checks → Reporting.  
**How:**
1. **`initialize()`** -- Connects to SQLite, creates the async HTTP client with rate limiting.
2. **`run(target, phases)`** -- Validates the target, stores it in the database, then runs each requested phase in sequence.
3. **`_run_recon()`** -- Calls subdomain enumeration, host probing, and endpoint collection.
4. **`_run_scanning()`** -- Runs port scanning, tech fingerprinting, and directory brute-forcing.
5. **`_run_fuzzing()`** -- Discovers hidden parameters and fuzzes endpoints.
6. **`_run_vuln_checks()`** -- Instantiates **10 vulnerability detectors** (XSS, SQLi, SSTI, SSRF, NoSQLi, CSRF, CORS, IDOR, Open Redirect, Misconfiguration) and runs each against every discovered endpoint. Findings are stored in the database with full evidence.
7. **`_run_reporting()`** -- Generates JSON and HTML reports from the stored findings.
8. **`_print_summary()`** -- Renders a final summary table with vulnerability counts and severity breakdown.

### `core/decision.py`
**What:** Smart decision engine that analyzes scan data and recommends next steps.  
**How:** Builds a `TargetProfile` from the discovered endpoints, technologies, and open ports. Produces prioritized recommendations like "Test for SQL injection on PHP endpoints" or "Focus XSS testing on search parameters." Also generates fuzzing configuration based on detected technologies.

### `core/scheduler.py`
**What:** Task scheduler and phase tracker.  
**How:** Manages phase status (`pending` → `running` → `completed`/`failed`/`skipped`), tracks timing per phase, enforces concurrency limits via `asyncio.Semaphore`, and provides a summary dict for the final report.

---

## 📂 `data/` -- Static Data

### `data/wordlists/common_subdomains.txt`
**What:** Wordlist of ~100 common subdomain prefixes (www, api, mail, dev, staging, etc.).  
**How:** Used by `SubdomainEnumerator` for brute-force subdomain discovery.

### `data/wordlists/common_dirs.txt`
**What:** Wordlist of ~100 common directory/file paths (/admin, /login, /.env, /api, /backup, etc.).  
**How:** Used by `DirectoryBruter` to discover hidden endpoints via HTTP requests.

### `data/wordlists/common_params.txt`
**What:** Wordlist of ~100 common HTTP parameter names (id, q, search, page, token, etc.).  
**How:** Used by `ParamDiscoverer` to brute-force hidden query parameters on endpoints.

---

## 📂 `database/` -- Persistence Layer

### `database/__init__.py`
**What:** Package marker.

### `database/schema.sql`
**What:** SQL schema defining 6 tables: `targets`, `subdomains`, `endpoints`, `scan_results`, `vulnerabilities`, and `logs`.  
**How:** Executed automatically on first run by `DatabaseManager.connect()`. Each table stores its phase's results with foreign key relationships (target → subdomain → endpoint → vulnerability).

### `database/models.py`
**What:** Python dataclasses (`Target`, `Subdomain`, `Endpoint`, `ScanResult`, `Vulnerability`) that map to the database tables.  
**How:** Each dataclass has typed fields matching the SQL columns. Used as structured transfer objects between the engine and the database manager.

### `database/manager.py`
**What:** Async database manager wrapping `aiosqlite`.  
**How:** Provides async CRUD methods:
- `connect()` / `close()` -- Lifecycle management
- `insert_target()`, `insert_subdomain()`, `insert_endpoint()`, `insert_vulnerability()` -- Store results
- `get_subdomains()`, `get_endpoints()`, `get_scan_results()` -- Retrieve data
- `has_phase_data()` -- Resume support (skip phases with existing data)
- `get_stats()` -- Aggregate counts and severity breakdown for reports

---

## 📂 `integrations/` -- External Tool Wrappers

> Optional wrappers for popular security tools. HexHunter degrades gracefully if these tools aren't installed -- it falls back to built-in Python logic.

### `integrations/__init__.py`
**What:** Package marker.

### `integrations/base.py`
**What:** Abstract base class (`ExternalTool`) for all integrations.  
**How:** Provides `is_available()` (checks if the binary exists in `$PATH`), `run()` (executes via `asyncio.create_subprocess_exec`), and `parse_output()` (abstract -- each tool implements its own parser). Handles timeouts and error capture.

### `integrations/subfinder.py`
**What:** Wrapper for [subfinder](https://github.com/projectdiscovery/subfinder) -- passive subdomain enumeration.  
**How:** Runs `subfinder -d <domain> -silent -json`, parses JSON output into a list of subdomain strings.

### `integrations/httpx.py`
**What:** Wrapper for [httpx](https://github.com/projectdiscovery/httpx) -- HTTP probing.  
**How:** Runs `httpx -l <hosts_file> -json -silent`, parses response status codes, titles, and technologies.

### `integrations/nuclei.py`
**What:** Wrapper for [nuclei](https://github.com/projectdiscovery/nuclei) -- template-based vulnerability scanning.  
**How:** Runs `nuclei -u <url> -json -silent`, parses vulnerability findings into HexHunter's standard finding format.

### `integrations/ffuf.py`
**What:** Wrapper for [ffuf](https://github.com/ffuf/ffuf) -- web fuzzer.  
**How:** Runs `ffuf -u <url>/FUZZ -w <wordlist> -json -silent`, parses discovered paths.

---

## 📂 `modules/` -- Scanning & Detection Logic

> The operational core -- organized into 4 phases matching the pipeline.

### `modules/__init__.py`
**What:** Package marker.

---

### 📁 `modules/recon/` -- Reconnaissance Phase

#### `modules/recon/__init__.py`
**What:** Package marker.

#### `modules/recon/subdomains.py`
**What:** Subdomain enumeration engine.  
**How:** Combines passive sources (crt.sh certificate transparency logs, web archives, DNS brute-force using the wordlist) to build a comprehensive subdomain list. Uses `asyncio.gather()` for concurrent queries. Deduplicates results before returning.

#### `modules/recon/hosts.py`
**What:** Host probing -- determines which subdomains are alive.  
**How:** Sends concurrent HTTP/HTTPS requests to each subdomain. Records status code, page title, IP address, and response time. Marks hosts as alive/dead for downstream phases.

#### `modules/recon/endpoints.py`
**What:** Endpoint collection via web crawling and passive sources.  
**How:** Crawls alive hosts by parsing HTML for links (`<a href>`, `<form action>`, `<script src>`). Also queries the Wayback Machine API for historical endpoints. Normalizes and deduplicates all discovered URLs.

#### `modules/recon/asn.py`
**What:** ASN (Autonomous System Number) lookup.  
**How:** Queries public ASN APIs to identify the target's IP ranges and network ownership. Helps discover additional assets belonging to the same organization.

---

### 📁 `modules/scanning/` -- Active Scanning Phase

#### `modules/scanning/__init__.py`
**What:** Package marker.

#### `modules/scanning/ports.py`
**What:** Async TCP port scanner.  
**How:** Uses `asyncio.open_connection()` to probe common ports (top 100) with configurable timeout. Identifies open ports, captures service banners via initial data read, and returns structured results.

#### `modules/scanning/fingerprint.py`
**What:** Technology fingerprinting engine.  
**How:** Analyzes HTTP response headers (`X-Powered-By`, `Server`), HTML meta tags, cookies, and JavaScript library signatures to identify the web stack (e.g., Apache, nginx, PHP, WordPress, React). Maps findings to known vulnerability profiles.

#### `modules/scanning/directories.py`
**What:** Directory brute-force scanner.  
**How:** Loads `common_dirs.txt` and sends concurrent HTTP requests to `<host>/<path>`. Filters results by status code (200, 301, 302, 403) and response size. Captures content-length for analysis.

#### `modules/scanning/services.py`
**What:** Service identification for open ports.  
**How:** Matches port numbers to known services (22=SSH, 80=HTTP, 3306=MySQL, etc.) and analyzes banners to determine software versions.

---

### 📁 `modules/fuzzing/` -- Fuzzing Phase

#### `modules/fuzzing/__init__.py`
**What:** Package marker.

#### `modules/fuzzing/payloads.py`
**What:** **The payload database** -- 246 curated payloads across 9 vulnerability categories.  
**How:** Defines static payload lists (`XSS_PAYLOADS`, `SQLI_PAYLOADS`, `SSTI_PAYLOADS`, `SSRF_PAYLOADS`, `NOSQLI_PAYLOADS`, `CSRF_PAYLOADS`, `CORS_PAYLOADS`, `IDOR_PAYLOADS`, `REDIRECT_PAYLOADS`) sourced from community repositories (PayloadBox, PayloadPlayground, OWASP). The `PayloadEngine` class provides:
- `get_payloads(category)` -- retrieve payloads by type
- `url_encode()` / `double_url_encode()` -- WAF bypass encoding
- `base64_encode()` / `html_encode()` -- alternative encodings
- `generate_poc(vuln_type, url, param, payload)` -- formatted Proof-of-Concept with reproduction steps

#### `modules/fuzzing/params.py`
**What:** Hidden parameter discovery.  
**How:** Injects a unique canary string into candidate parameter names from the wordlist. If the canary appears reflected in the response, or the response differs from baseline (status code change, size difference >100 bytes), the parameter is confirmed as active. Uses `asyncio.Semaphore(20)` for concurrency control.

#### `modules/fuzzing/endpoints.py`
**What:** Endpoint fuzzer -- discovers hidden paths and API routes.  
**How:** Generates URL variations with common extensions (`.php`, `.json`, `.bak`, `.old`) and path mutations. Sends concurrent requests and captures new endpoints based on response codes.

#### `modules/fuzzing/wordlists.py`
**What:** Wordlist manager.  
**How:** Loads, merges, and deduplicates wordlists from the `data/wordlists/` directory. Supports custom wordlist paths via configuration.

---

### 📁 `modules/vulns/` -- Vulnerability Detection Phase

> Each detector follows the same interface: `__init__(http_client)` and `async detect(url) -> list[dict]`.

#### `modules/vulns/__init__.py`
**What:** Package marker.

#### `modules/vulns/xss.py` -- Cross-Site Scripting
**What:** Detects reflected and DOM-based XSS.  
**How:**
1. Injects a canary string into each parameter
2. Checks if the canary is reflected in the HTML response
3. Determines the reflection context (HTML body, attribute, script block, comment)
4. Sends context-appropriate payloads from `PayloadEngine.get_payloads("xss")`
5. Verifies dangerous characters (`<script`, `onerror=`) survived encoding
6. Scans JavaScript for DOM XSS source-sink patterns (`document.URL` → `innerHTML`)

#### `modules/vulns/sqli.py` -- SQL Injection
**What:** Detects error-based SQL injection with multi-database support.  
**How:**
1. Gets baseline response for each parameter
2. Appends SQL payloads from `PayloadEngine.get_payloads("sqli")`
3. Scans response body for database error patterns (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
4. Validates by ensuring the error wasn't present in the baseline
5. Identifies the database type from the error signature

#### `modules/vulns/ssti.py` -- Server-Side Template Injection
**What:** Detects SSTI and identifies the template engine.  
**How:**
1. Injects arithmetic probes (`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`) into each parameter
2. Checks if the computed value (`49`) appears in the response
3. Validates the value wasn't in the baseline (false positive elimination)
4. Identifies the engine (Jinja2, Twig, FreeMarker, ERB) based on which probe triggered
5. Severity is **Critical** because SSTI typically leads to Remote Code Execution

#### `modules/vulns/ssrf.py` -- Server-Side Request Forgery
**What:** Detects SSRF via cloud metadata and internal service probing.  
**How:**
1. Identifies URL-accepting parameters (names like `url`, `src`, `callback`, `file`, `proxy`)
2. Injects SSRF payloads: AWS/GCP/Azure metadata URLs, localhost IP bypasses (decimal, hex, octal, IPv6), protocol smuggling (`file://`, `gopher://`, `dict://`)
3. Detects success via: cloud metadata keywords in response (`ami-id`, `security-credentials`), timing anomalies (>3s vs. baseline), significant response size differences
4. Severity is **Critical** for confirmed data leakage, **Medium** for blind/timing

#### `modules/vulns/nosqli.py` -- NoSQL Injection
**What:** Detects MongoDB/CouchDB injection via operator abuse.  
**How:**
1. **URL parameter testing:** Appends MongoDB operators (`[$ne]=`, `[$gt]=`, `[$regex]=.*`) to parameter names
2. **JSON body testing:** Sends POST requests with operator-injected JSON (`{"username": {"$ne": ""}, "password": {"$ne": ""}}`)
3. Detects auth bypass by comparing response status (401→200) and checking for success keywords (`welcome`, `dashboard`, `token`)
4. Severity is **Critical** because it typically bypasses authentication

#### `modules/vulns/csrf.py` -- Cross-Site Request Forgery
**What:** Detects missing CSRF protection on state-changing forms.  
**How:**
1. Parses all `<form>` tags from the HTML response
2. Filters to state-changing methods (POST, PUT, DELETE, PATCH)
3. Checks if any hidden input field matches known CSRF token names (`csrf_token`, `_csrf`, `authenticity_token`, etc.)
4. Analyses `Set-Cookie` headers for missing `SameSite` attribute on session cookies
5. Generates an auto-submit HTML PoC form for each vulnerable endpoint

#### `modules/vulns/cors.py` -- CORS Misconfiguration
**What:** Deep CORS testing with multiple origin variants.  
**How:**
1. Builds a list of malicious `Origin` headers: attacker domain, `null`, subdomain suffix match (`target.com.evil.com`), prefix match (`eviltarget.com`), null-byte injection
2. Sends each origin and inspects `Access-Control-Allow-Origin` (ACAO) and `Access-Control-Allow-Credentials` (ACAC)
3. Severity mapping:
   - **Critical:** ACAO reflects attacker origin + ACAC: true (credential theft possible)
   - **Medium:** ACAO reflects attacker origin without credentials, or allows `null`
   - **Low:** Wildcard `*` without credentials

#### `modules/vulns/idor.py` -- Insecure Direct Object Reference
**What:** Detects IDOR patterns via sequential ID testing.  
**How:**
1. Identifies numeric ID parameters by name (`id`, `user_id`, `order`, etc.) and value pattern
2. Tests adjacent IDs (id-1, id+1, id+100)
3. Compares response status, body size, and content to detect different objects being returned
4. Also scans URL paths for sequential patterns (`/users/123`)

#### `modules/vulns/redirect.py` -- Open Redirect
**What:** Detects open redirect vulnerabilities via parameter injection.  
**How:**
1. Identifies redirect parameters (from URL or common names: `url`, `redirect`, `next`, `return`, etc.)
2. Injects external domain payloads (`//evil.com`, `/\evil.com`, `https://evil.com@victim.com`)
3. Sends request with `follow_redirects=False` to inspect the `Location` header
4. Also checks for client-side redirects via meta refresh and `window.location`

#### `modules/vulns/misconfig.py` -- Security Misconfiguration
**What:** Checks for missing security headers, information disclosure, and basic CORS issues.  
**How:**
1. **Security headers:** Checks for HSTS, X-Content-Type-Options, X-Frame-Options, CSP, Referrer-Policy, Permissions-Policy
2. **Information disclosure:** Flags revealing headers (`X-Powered-By`, `Server`, `X-AspNet-Version`)
3. **CORS baseline:** Tests a single evil origin (complemented by the dedicated `cors.py` detector for deep testing)

---

## 📂 `reports/` -- Report Generation

### `reports/__init__.py`
**What:** Package marker.

### `reports/generator.py`
**What:** Multi-format report generator.  
**How:** Queries the database for all findings, groups them by severity, and produces:
- **JSON report** -- Machine-readable, structured data for CI/CD integration
- **HTML report** -- Professional, styled report using Jinja2 templates

### `reports/sample_output.json`
**What:** Example JSON report showing the expected output structure.  
**How:** Demonstrates the finding format: type, severity, title, description, evidence, request/response data, and reproduction steps.

### `reports/templates/report.html`
**What:** Jinja2 HTML template for the visual report.  
**How:** Renders a dark-themed, professional HTML document with:
- Executive summary with severity counters
- Color-coded vulnerability cards (critical=red, high=orange, medium=yellow, low=blue)
- Expandable evidence sections with request/response data
- Gradient header with glassmorphism effects

---

## 📂 `utils/` -- Shared Utilities

### `utils/__init__.py`
**What:** Package marker.

### `utils/network.py`
**What:** Async HTTP client with retry, rate limiting, and evidence capture.  
**How:** Built on `aiohttp`. Features:
- **`RateLimiter`** -- Token-bucket algorithm limiting requests per second
- **`AsyncHTTPClient`** -- GET/POST/HEAD methods with automatic retry (exponential backoff), configurable timeouts, redirect control, and SSL verification toggle
- **`HTTPResponse`** dataclass -- Captures URL, status, headers, body, timing, and redirect chain for evidence storage
- **`HTTPRequest`** dataclass -- Structured request representation for PoC reproduction

### `utils/logger.py`
**What:** Custom logging system with rich terminal output.  
**How:** Uses `rich` for colorized console output with custom log levels:
- `logger.finding(severity, type, url, detail)` -- Styled vulnerability alerts
- `logger.success()` / `logger.warning()` / `logger.critical()` -- Phase status
- Writes to both console and daily log file (`logs/hexhunter_YYYYMMDD.log`)

### `utils/validators.py`
**What:** Input validation and sanitization.  
**How:** Validates targets as domain, IP address, CIDR range, or URL using regex and the `ipaddress` module. Returns a `ValidationResult` with normalized target, detected type (`TargetType` enum), extracted domain/IP, and any validation errors.

### `utils/parsers.py`
**What:** Response parsing utilities.  
**How:** Extracts structured data from HTML responses: page titles, links, forms, meta tags, and comments. Used by recon and vuln modules.

### `utils/helpers.py`
**What:** General-purpose helper functions.  
**How:** Provides `load_wordlist()` (file reader with deduplication), `is_ip()`, `normalize_url()`, `extract_domain()`, and timing utilities used across all modules.

---

## 📂 `logs/` -- Runtime Logs

### `logs/hexhunter_YYYYMMDD.log`
**What:** Daily log file capturing all scan activity.  
**How:** Auto-created by the logger. Contains timestamped entries for every phase, finding, and error. Useful for post-scan forensics and debugging.

---

## 🔄 Execution Flow

```
main.py
  └── HexHunterEngine.run()
        ├── Phase 1: RECON
        │     ├── subdomains.py   → enumerate subdomains
        │     ├── hosts.py        → probe alive hosts
        │     └── endpoints.py    → collect URLs
        ├── Phase 2: SCAN
        │     ├── ports.py        → TCP port scan
        │     ├── fingerprint.py  → tech detection
        │     └── directories.py  → directory brute-force
        ├── Phase 3: FUZZ
        │     ├── params.py       → discover hidden params
        │     └── endpoints.py    → fuzz paths
        ├── Phase 4: VULN
        │     ├── xss.py          → XSS detection
        │     ├── sqli.py         → SQL injection
        │     ├── ssti.py         → template injection
        │     ├── ssrf.py         → SSRF detection
        │     ├── nosqli.py       → NoSQL injection
        │     ├── csrf.py         → CSRF detection
        │     ├── cors.py         → CORS misconfig
        │     ├── idor.py         → IDOR detection
        │     ├── redirect.py     → open redirect
        │     └── misconfig.py    → header checks
        └── Phase 5: REPORT
              └── generator.py    → JSON + HTML output
```
