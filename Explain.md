# HexHunterX — Deep Technical Explanation

> **How everything works, in the order it actually runs, including the AI layer.**

---

## Table of Contents
1. [High-Level Architecture](#1-high-level-architecture)
2. [Entry Point & CLI](#2-entry-point--cli)
3. [Configuration Loading](#3-configuration-loading)
4. [Core Engine — The Orchestrator](#4-core-engine--the-orchestrator)
5. [Phase 1 — Reconnaissance](#5-phase-1--reconnaissance)
6. [Phase 2 — Scanning](#6-phase-2--scanning)
7. [Phase 3 — Fuzzing](#7-phase-3--fuzzing)
8. [Phase 4 — Vulnerability Detection](#8-phase-4--vulnerability-detection)
9. [Verification Framework](#9-verification-framework)
10. [Deduplication Pipeline](#10-deduplication-pipeline)
11. [AI Integration Layer](#11-ai-integration-layer)
12. [Database Layer](#12-database-layer)
13. [Reporting](#13-reporting)
14. [Utilities](#14-utilities)
15. [Complete Call Sequence (Full Scan)](#15-complete-call-sequence-full-scan)

---

## 1. High-Level Architecture

```
User CLI
    │
    ▼
main.py ──────── load config/default.yaml
    │
    ▼
HexHunterXEngine (core/engine.py)
    │
    ├─► Phase 1: Recon        → modules/recon/
    ├─► Phase 2: Scanning     → modules/scanning/
    ├─► Phase 3: Fuzzing      → modules/fuzzing/
    ├─► Phase 4: Vuln Checks  → modules/vulns/
    │       │
    │       ├─► Verification  → modules/vulns/verification.py
    │       ├─► Deduplication → modules/vulns/deduplication.py
    │       └─► AI Triage     → ai/triage.py ──► ai/client.py ──► Google AI Studio
    │
    └─► Phase 5: Reporting    → reports/generator.py
                                    └─► reports/templates/report.html
```

All phases write their findings into an **SQLite database** (`database/`),  
and the next phase reads from that database to build on previous results.

---

## 2. Entry Point & CLI

### `main.py`
The main entry point. Its job is:
1. Parse CLI arguments via `cli/interface.py`
2. Load `config/default.yaml` via `load_config()`
3. Apply any CLI overrides (e.g. `--threads 100`) via `apply_cli_overrides()`
4. Initialize `HexHunterXEngine(config)` and call `engine.run()`

### `cli/interface.py`
Defines all command-line flags using Python's `argparse`.  
Key flag groups:
- **Scan Phases**: `--recon`, `--scan`, `--fuzz`, `--vuln`, `--full-scan`
- **Configuration**: `--config`, `--threads`, `--timeout`, `--rate-limit`
- **Auth**: `--cookie`, `--auth-token`, `--login-url`, `--login-user`, `--login-pass`
- **OOB Detection**: `--oob`, `--oob-server`, `--oob-token`
- **AI Integration**: `--ai`, `--ai-triage`, `--ai-key`
- **Output**: `--output`, `--format`, `--silent`

Returns a flat `dict` of settings consumed by `main.py`.

---

## 3. Configuration Loading

### `config/default.yaml`
The single source of truth for default settings. Key sections:

```yaml
general:   # threads, timeout, rate_limit, user_agent
database:  # SQLite path
recon:     # passive sources, wordlists, subdomain limits
scanning:  # port count, directory wordlists, extensions
fuzzing:   # param wordlists, depth limits
vulnerability: # which checks to run, payload limits
reporting: # output directory, formats (json/html)
integrations:  # subfinder, httpx, ffuf, nuclei settings
ai:
  provider: "google"          # "google" = AI Studio, "openrouter" = OpenRouter
  api_key:  "AIza..."
  model:    "gemma-4-26b-a4b-it" # Available on free-tier keys
  enabled:  true
```

`main.py` merges CLI overrides **on top** of this config so the YAML is the default and the CLI wins.

---

## 4. Core Engine — The Orchestrator

### `core/engine.py` → `HexHunterXEngine`

The central class that drives the entire pipeline. Key methods in execution order:

| Method | What It Does |
|---|---|
| `__init__(config)` | Stores config, creates `DatabaseManager`, `TaskScheduler`, `DecisionEngine` |
| `initialize()` | Connects DB, starts HTTP client, sets up auth, OOB, and AI |
| `run(target, phases)` | Validates target, stores it in DB, then calls each phase method |
| `_run_recon()` | Orchestrates subdomain enumeration and host discovery |
| `_run_scanning()` | Orchestrates port scanning, fingerprinting, directory scanning |
| `_run_fuzzing()` | Orchestrates parameter discovery and endpoint fuzzing |
| `_run_vuln_checks()` | Runs all 10 vulnerability detectors, deduplicates, AI-triages, stores findings |
| `_run_reporting()` | Generates JSON + HTML reports |
| `shutdown()` | Closes HTTP client, stops OOB polling, disconnects DB |

**AI Setup** happens inside `initialize()`:
```python
from ai.client import set_api_key, set_model, set_provider
set_api_key(ai_config["api_key"])
set_model(ai_config["model"])
set_provider(ai_config["provider"])   # "google" or "openrouter"
```

### `core/decision.py` → `DecisionEngine`
A rule-based engine that analyses the target profile (domain, IP, cloud provider, detected technologies) and adjusts scanning aggressiveness. For example, it might tell the engine to skip certain checks if the target looks like a CDN-only host, or to go deeper if it detects a PHP/MySQL stack.

### `core/scheduler.py` → `TaskScheduler`
Manages the async task concurrency pool. Wraps `asyncio.Semaphore` to cap the number of simultaneous HTTP requests across all modules according to `config.general.threads`.

---

## 5. Phase 1 — Reconnaissance

**Directory**: `modules/recon/`

| File | Class | What It Does |
|---|---|---|
| `subdomains.py` | `SubdomainEnumerator` | Queries passive DNS sources (crt.sh, HackerTarget), optionally runs subfinder |
| `hosts.py` | `HostDiscovery` | Resolves subdomains to IPs, probes HTTP/HTTPS to check if alive |
| `endpoints.py` | `EndpointDiscoverer` | Crawls alive hosts for known endpoint paths (sitemaps, robots.txt, JS files) |
| `asn.py` | `ASNLookup` | Identifies ASN and IP ranges associated with the target |

**Data Flow**:
```
SubdomainEnumerator → DB: subdomains table
HostDiscovery       → DB: updates is_alive, status_code, title per subdomain
EndpointDiscoverer  → DB: endpoints table
```

---

## 6. Phase 2 — Scanning

**Directory**: `modules/scanning/`

| File | Class | What It Does |
|---|---|---|
| `ports.py` | `PortScanner` | Async TCP connect scan on top N ports |
| `fingerprint.py` | `TechFingerprinter` | Reads Server, X-Powered-By, cookies, headers to identify the tech stack |
| `directories.py` | `DirectoryScanner` | Brute-forces common paths using `data/wordlists/common_dirs.txt` |
| `services.py` | `ServiceDetector` | Banner-grabs open ports to identify service versions |

**Data Flow**:
```
PortScanner        → DB: scan_results table (port, protocol, service, state)
TechFingerprinter  → DB: updates subdomains.tech_stack
DirectoryScanner   → DB: endpoints table (source="directory_scan")
```

The `DecisionEngine` reads the `tech_stack` from the `TechFingerprinter` output and uses it to make smarter decisions about which vulnerability checks to prioritise later.

---

## 7. Phase 3 — Fuzzing

**Directory**: `modules/fuzzing/`

| File | Class | What It Does |
|---|---|---|
| `params.py` | `ParamDiscoverer` | Discovers hidden GET/POST parameters on each endpoint |
| `endpoints.py` | `EndpointFuzzer` | Extends directory scanning with extension-based fuzzing (`.php`, `.bak`, etc.) |
| `payloads.py` | `PayloadEngine` | Central payload library (XSS, SQLi, SSTI, SSRF, etc.) |
| `wordlists.py` | `WordlistManager` | Loads and rotates wordlists from `data/wordlists/` |

### `PayloadEngine` (key class)
Holds the static payload library. Key methods:
- `get_payloads(category, encoded=False)` — returns the static payload list
- `generate_poc(vuln_type, url, param, payload)` — generates a reproduction PoC string

---

## 8. Phase 4 — Vulnerability Detection

**Directory**: `modules/vulns/`

This is the most important phase. The engine iterates over every alive host and every discovered endpoint, then runs each detector.

### The 10 Detectors

| File | Detector | Method |
|---|---|---|
| `xss.py` | `XSSDetector` | Injects canary, checks reflection context, tests executable payloads |
| `sqli.py` | `SQLiDetector` | Error-based (regex on DB errors), boolean-blind (diff responses), time-blind (delay measurement) |
| `ssti.py` | `SSTIDetector` | Injects math expressions, verifies evaluated output (e.g. `{{7*7}}` → `49`) |
| `ssrf.py` | `SSRFDetector` | Injects OOB/internal URL payloads, uses Interactsh for blind detection |
| `idor.py` | `IDORDetector` | Increments/decrements ID parameters, checks for PII or unauthorized data access |
| `nosqli.py` | `NoSQLiDetector` | Tests MongoDB operator injection, requires 401→200 status code flip |
| `cors.py` | `CORSDetector` | Tests reflected Origin header in `Access-Control-Allow-Origin` response |
| `csrf.py` | `CSRFDetector` | Detects sensitive forms without CSRF tokens on state-changing actions |
| `redirect.py` | `OpenRedirectDetector` | Injects URL payloads into redirect parameters, verifies `Location` header |
| `misconfig.py` | `MisconfigDetector` | Checks for exposed admin panels, debug endpoints, sensitive file paths |

### Shared Detection Pattern (all detectors follow this)
```
1. Parse URL → extract EXISTING parameters (no parameter invention)
2. Fetch baseline response (no payload)
3. Inject payload into one parameter
4. Compare injected response to baseline
5. If different in a meaningful way → potential finding
6. Re-verify once more (retry confirmation)
7. Score confidence using ConfidenceScorer
8. Return finding dict with type, severity, evidence, request, response
```

---

## 9. Verification Framework

### `modules/vulns/verification.py`

The shared library used by every detector. It eliminates false positives by providing rigorous comparison tools.

#### `ResponseNormalizer`
Strips dynamic content (CSRF tokens, session IDs, timestamps, random nonces) from response bodies **before** comparison. This prevents false negatives caused by tokens changing between requests.

#### `ResponseAnalyzer`
Compares two responses:
- `similarity(a, b)` — uses `SequenceMatcher` to get a ratio (0.0–1.0)
- `is_same_response(a, b)` — true if similarity ≥ threshold (default 0.90)
- `response_changed_meaningfully(baseline, test)` — true only if both similarity dropped **and** size difference exceeds 200 bytes (prevents noise)

#### `TimingAnalyzer`
For time-based blind injection:
- Sends N baseline requests, measures median time
- Sends N injected requests, measures median time
- Flags as significant only if **all** injected times exceed `threshold_ms` (default 4 seconds) with jitter tolerance of 30%

#### `ConfidenceScorer`
Combines multiple verification signals into a 4-tier confidence level:

| Confidence | Minimum Score | Meaning |
|---|---|---|
| `confirmed` | 0.70 | Multiple independent verifications passed |
| `high` | 0.50 | Primary signal + retry confirmed |
| `medium` | 0.30 | Primary signal only |
| `low` | 0.0 | Weak indication |

---

## 10. Deduplication Pipeline

### `modules/vulns/deduplication.py` → `FindingDeduplicator`

After all detectors run, findings are collected into the deduplicator before being written to the database.

**What it does**:
1. Normalises each finding into a canonical key: `(vuln_type, parameter, base_url)`
2. If a duplicate key appears, it keeps only the **highest confidence** finding
3. Suppresses findings that exceed `max_findings` per host (default: 50)
4. Filters out findings below `min_confidence` threshold (default: `medium`)

**Why this matters**: Without it, a single injectable parameter could generate 50+ identical findings from different payloads in the same category.

```python
# Inside engine._run_vuln_checks():
deduplicator = FindingDeduplicator(max_findings=50, min_confidence="medium")

for vuln in detector.detect(url):
    deduplicator.add(vuln)

final_findings = deduplicator.get_findings()  # clean, de-duplicated list
```

---

## 11. AI Integration Layer

**Directory**: `ai/`

The AI layer is the final decision-maker that acts like a senior security engineer reviewing each finding.

### Architecture

```
engine._run_vuln_checks()
    │
    └─► deduplicator.get_findings()   ← clean findings
            │
            └─► for each finding:
                    └─► ai/triage.py → triage_finding()
                            │
                            └─► ai/client.py → ask_ai_async()
                                    │
                                    ├─► Google AI Studio  (provider="google")
                                    │   POST /v1beta/models/gemma-3-27b-it:generateContent
                                    │
                                    └─► OpenRouter        (provider="openrouter")
                                        POST /api/v1/chat/completions
```

### `ai/client.py` — The Provider Abstraction

Handles both providers with a unified interface. Key functions:

| Function | Description |
|---|---|
| `set_api_key(key)` | Sets the API key (called from engine during init) |
| `set_model(model)` | Sets the model name (e.g. `gemma-4-26b-it`) |
| `set_provider(provider)` | Switches between `"google"` and `"openrouter"` |
| `ask_ai(prompt, system)` | Synchronous call — used in tests |
| `ask_ai_async(prompt, system)` | Async call — used during live scans |

**Google AI Studio request format**:
```python
POST https://generativelanguage.googleapis.com/v1beta/models/gemma-3-27b-it:generateContent?key=AIza...
{
  "contents": [
    {"role": "user", "parts": [{"text": "<system prompt>"}]},
    {"role": "model", "parts": [{"text": "Understood."}]},
    {"role": "user", "parts": [{"text": "<finding details>"}]}
  ]
}
```

**OpenRouter request format**:
```python
POST https://openrouter.ai/api/v1/chat/completions
Authorization: Bearer sk-or-...
{
  "model": "google/gemma-4-26b-a4b-it:free",
  "messages": [
    {"role": "system", "content": "..."},
    {"role": "user", "content": "..."}
  ]
}
```

### `ai/triage.py` — False Positive Filter

The most critical AI module. For each finding, it sends:
- The **vulnerability type**
- The **payload used**
- The **raw HTTP request** sent by the scanner
- The **first 2000 characters of the HTTP response**

The AI responds with structured JSON:
```json
{
  "verdict": "TRUE_POSITIVE",
  "confidence": "HIGH",
  "reasoning": "The MySQL error message in the response contains the injected quote, confirming unparameterised SQL query execution.",
  "recommendation": "Extract the full database schema using UNION-based injection."
}
```

**The system prompt** instructs the model to:
> Be critical. Automated scanners often report false positives. If it looks like a generic error, WAF block, coincidental reflection, or non-exploitable context, mark it FALSE_POSITIVE.

Because LLMs (like Gemma) often wrap their JSON output in Markdown code blocks (e.g., ` ```json ... ``` `) or add conversational text, `ai/triage.py` uses a **robust 4-strategy JSON extractor**:
1. Direct `json.loads()` attempt
2. Stripping Markdown fences and re-parsing
3. Regex extraction of the first `{ ... }` block containing the key `"verdict"`
4. Keyword inference fallback (e.g., parsing raw text for "true positive" if JSON parsing fails entirely)

The engine then uses the verdict to decide whether to write the finding to the database:

```python
# Only write if AI says TRUE_POSITIVE, or if AI is disabled (graceful degradation)
if ai_triage_data:
    v["ai_triage"] = ai_triage_data
# Finding is always stored — the ai_triage field provides metadata
```

### `ai/anomaly.py` — Statistical HTTP Monitor

Monitors response times and sizes across the scan using rolling statistics (mean + standard deviation). Flags anomalous responses as potential indicators of:
- Blind injection (sudden time spikes)
- Data exfiltration (sudden size increases)
- WAF/IDS changes in behaviour

Uses Python's `statistics` module — no external dependency.

### `ai/payloads.py` — Context-Aware Payload Generator (optional)
When enabled, asks the AI to generate targeted payloads tuned to the detected tech stack and WAF. Currently disabled by default (controlled by `config["ai_payloads"]`).

---

## 12. Database Layer

**Directory**: `database/`

| File | Purpose |
|---|---|
| `schema.sql` | Defines all tables — targets, subdomains, endpoints, scan_results, vulnerabilities, logs |
| `models.py` | Python dataclasses matching each table (Target, Subdomain, Endpoint, ScanResult, Vulnerability) |
| `manager.py` | Async SQLite wrapper (`DatabaseManager`) with all insert/query methods |

### Key Tables

```sql
targets        (id, domain, ip, cidr, target_type, created_at)
subdomains     (id, target_id, name, ip, is_alive, status_code, title, tech_stack)
endpoints      (id, subdomain_id, url, method, params, source)
scan_results   (id, subdomain_id, port, protocol, service, version, state)
vulnerabilities(id, target_id, subdomain_id, endpoint_id,
                vuln_type, severity, title, description,
                evidence, request, response, reproduction,
                confidence, verification_method, ai_triage,
                created_at)
logs           (id, target_id, phase, message, created_at)
```

The `ai_triage` column stores the JSON verdict from the AI as a text blob.

---

## 13. Reporting

**Directory**: `reports/`

### `reports/generator.py` → `ReportGenerator`

After all phases complete, the engine calls `generator.generate(target_id, output_dir)`:

1. **Gather** — queries all tables for the target from the database
2. **JSON report** — serialises the full data dict to `HexHunterX_report_<domain>.json`
3. **HTML report** — renders `reports/templates/report.html` via Jinja2

### `reports/templates/report.html`

A self-contained dark-theme HTML file. Key features added in the recent rewrite:
- **Header** — target name, date, scan ID, and the **AI Model used**
- **Summary Cards** — subdomains, hosts, endpoints, ports, vulnerabilities
- **Severity Bar** — critical/high/medium/low/info counts
- **Vulnerabilities** — collapsible cards per finding with evidence, now displaying the **AI Triage Verdict** (Confirmed/FP/?) as coloured badges.
- **Alive Subdomains** — responsive table with HTTP status code color-coding
- **Dead Subdomains** — responsive table
- **Open Ports** — responsive table
- **Discovered Endpoints** — responsive table listing all discovered URLs, methods, and parameters.
- **Footer** — version and disclaimer

The template is rendered securely using a `jinja2.Environment` with `FileSystemLoader`, and tables are wrapped in `.table-responsive` divs with `overflow-x: auto` to prevent layout crashes on smaller viewports.

---

## 14. Utilities

**Directory**: `utils/`

| File | Class/Function | Purpose |
|---|---|---|
| `network.py` | `AsyncHTTPClient` | Async HTTP client with rate limiting, retries, session management. All detectors use this. |
| `logger.py` | `HexHunterXLogger`, `console` | Rich-based coloured logging with level support. `console` is the shared Rich `Console` instance. |
| `validators.py` | `InputValidator` | Validates and normalises targets (domain, IP, CIDR, URL). Returns `TargetType` enum. |
| `auth.py` | `AuthManager` | Handles cookie injection, Bearer token auth, and form-based auto-login. |
| `helpers.py` | `ensure_dir`, `save_json` | File system helpers used by the report generator. |
| `parsers.py` | — | HTML/JS parsers for extracting endpoints and forms from crawled pages. |

### `AsyncHTTPClient` — the backbone of all scanning

Every request in HexHunterX flows through this client. It provides:
- **Rate limiting** via token bucket (requests per second)
- **Automatic retries** with exponential backoff
- **Connection pooling** for efficiency
- **Timing measurement** — records `elapsed_ms` per request (used by `TimingAnalyzer`)
- **Auth injection** — cookies and headers applied globally
- **Returns** a response object with `status_code`, `body`, `headers`, `elapsed_ms`, `error`

---

## 15. Complete Call Sequence (Full Scan)

This is the exact order functions execute during `python main.py -t target.com --full-scan`:

```
main.py::main()
  └─► asyncio.run(run())
        ├─► parse_args()                          cli/interface.py
        ├─► load_config("config/default.yaml")   main.py
        ├─► apply_cli_overrides(config, args)     main.py
        │     └─► sets config["ai_triage"] = True (if ai.enabled)
        │
        └─► HexHunterXEngine(config).__init__()   core/engine.py
              └─► engine.run(target, phases)
                    │
                    ├─► engine.initialize()
                    │     ├─► DatabaseManager.connect()         database/manager.py
                    │     ├─► AsyncHTTPClient.start()           utils/network.py
                    │     ├─► AuthManager.from_config()         utils/auth.py (if auth set)
                    │     ├─► InteractshClient.register()       integrations/interactsh.py (if OOB)
                    │     └─► set_api_key() / set_model() / set_provider()   ai/client.py
                    │
                    ├─► InputValidator.validate(target)         utils/validators.py
                    ├─► DatabaseManager.insert_target()         database/manager.py
                    │
                    ├─► engine._run_recon()
                    │     ├─► SubdomainEnumerator.enumerate()   modules/recon/subdomains.py
                    │     ├─► HostDiscovery.probe()             modules/recon/hosts.py
                    │     ├─► EndpointDiscoverer.discover()     modules/recon/endpoints.py
                    │     └─► DatabaseManager.insert_subdomain() / insert_endpoint()
                    │
                    ├─► engine._run_scanning()
                    │     ├─► PortScanner.scan()                modules/scanning/ports.py
                    │     ├─► TechFingerprinter.fingerprint()   modules/scanning/fingerprint.py
                    │     ├─► DirectoryScanner.scan()           modules/scanning/directories.py
                    │     └─► DatabaseManager.insert_scan_result()
                    │
                    ├─► engine._run_fuzzing()
                    │     ├─► ParamDiscoverer.discover()        modules/fuzzing/params.py
                    │     ├─► EndpointFuzzer.fuzz()             modules/fuzzing/endpoints.py
                    │     └─► DatabaseManager.insert_endpoint()
                    │
                    ├─► engine._run_vuln_checks()               ← CORE PIPELINE
                    │     │
                    │     ├─► [for each alive subdomain]:
                    │     │     └─► [for each detector]:
                    │     │           └─► detector.detect(url)
                    │     │                 ├─► AsyncHTTPClient.get(baseline_url)
                    │     │                 ├─► AsyncHTTPClient.get(injected_url)
                    │     │                 ├─► ResponseAnalyzer.similarity()      verification.py
                    │     │                 ├─► TimingAnalyzer.verify_timing()     verification.py
                    │     │                 └─► ConfidenceScorer.score(signals)    verification.py
                    │     │
                    │     ├─► FindingDeduplicator.add(finding)  deduplication.py
                    │     ├─► FindingDeduplicator.get_findings() → final_findings
                    │     │
                    │     └─► [for each final_finding]:
                    │           ├─► triage_finding(...)          ai/triage.py
                    │           │     └─► ask_ai_async(prompt)   ai/client.py
                    │           │           └─► POST → Google AI Studio / OpenRouter
                    │           │                 └─► returns {"verdict": "TRUE_POSITIVE", ...}
                    │           └─► DatabaseManager.insert_vulnerability()
                    │
                    ├─► engine._run_reporting()
                    │     └─► ReportGenerator.generate()         reports/generator.py
                    │           ├─► DatabaseManager.get_vulnerabilities()
                    │           ├─► save_json(report_data)       utils/helpers.py
                    │           └─► Jinja2.Template(report.html).render() → HTML file
                    │
                    └─► engine.shutdown()
                          ├─► AsyncHTTPClient.close()
                          ├─► InteractshClient.deregister() (if OOB)
                          └─► DatabaseManager.close()
```

---

## Key Design Principles

| Principle | How It's Implemented |
|---|---|
| **No false parameter invention** | Every detector uses `parse_qs(url)` and only injects into EXISTING parameters |
| **Retry confirmation** | All positive findings are re-tested once before being flagged |
| **Statistical timing** | Time-blind injection requires consistent delay across 3 trials |
| **Baseline diffing** | Normalised response comparison strips tokens to avoid noise |
| **Graceful AI degradation** | If the AI API fails, the finding is still saved — just without AI verdict |
| **Global deduplication** | One `FindingDeduplicator` per scan aggregates all detector output before DB write |
| **Async first** | `AsyncHTTPClient` + `asyncio` throughout — no blocking I/O during scans |
