<div align="center">
<pre>
██╗  ██╗███████╗██╗  ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ ██╗  ██╗
██║  ██║██╔════╝╚██╗██╔╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗╚██╗██╔╝
███████║█████╗   ╚███╔╝ ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝ ╚███╔╝
██╔══██║██╔══╝   ██╔██╗ ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗ ██╔██╗
██║  ██║███████╗██╔╝ ██╗██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
</pre>
<h3>Modular Penetration Testing Framework</h3>
<p>
<a href="https://python.org"><img src="https://img.shields.io/badge/Python-3.10+-blue.svg" alt="Python"></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License"></a>
<img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg" alt="Platform">
<img src="https://img.shields.io/badge/Payloads-246-red.svg" alt="Payloads">
<img src="https://img.shields.io/badge/Vuln%20Detectors-10-orange.svg" alt="Detectors">
</p>
<p><em>A semi-automated pentesting framework for bug bounty hunters and red teams.</em></p>
</div>

---

## 🎯 Overview

**HexHunterX** is a production-grade, modular penetration testing framework that automates reconnaissance, scanning, fuzzing, and vulnerability detection while assisting human decision-making through structured reporting and a smart decision engine.

Built with clean architecture, async-first design, and extensible module system -- suitable for real-world bug bounty workflows and red team engagements.

> ⚠️ **Legal Disclaimer**: This tool is designed for **authorized security testing only**. Always obtain proper written authorization before testing any target. Unauthorized use is illegal and unethical.

---

## ✨ Features

| Category | Capabilities |
|----------|-------------|
| **Recon** | Subdomain enumeration (passive + active + permutations), live host probing, ASN mapping, endpoint collection (crawling + JS parsing + Wayback Machine) |
| **Scanning** | Async port scanning, service detection, directory brute-force, technology fingerprinting |
| **Fuzzing** | Parameter discovery, hidden endpoint detection, wordlist management, 246-payload injection engine |
| **Vulnerability Detection** | 10 detectors: XSS, SQLi, SSTI, SSRF, NoSQLi, CSRF, CORS, IDOR, Open Redirect, Misconfiguration |
| **Authenticated Scanning** | Cookie, JWT/Bearer, custom header, and auto-login (form POST with CSRF extraction) |
| **Blind/OOB Detection** | Interactsh integration for blind SSRF, blind SQLi, blind SSTI, and blind/stored XSS via DNS/HTTP callbacks |
| **Integrations** | subfinder, httpx, ffuf, nuclei, Interactsh (graceful fallback to built-in alternatives) |
| **Reporting** | Professional HTML reports, structured JSON output, severity classification, evidence capture |
| **Intelligence** | Smart decision engine adapts scanning based on target profile |
| **Performance** | Async I/O, rate limiting, connection pooling, retry with backoff, deduplication |
| **Storage** | SQLite persistence, scan resume, full CRUD operations |

---

## 🏗️ Architecture

```
HexHunterX/
├── main.py                          # Entry point
├── requirements.txt                 # Dependencies
├── config/
│   └── default.yaml                 # Configuration
│
├── core/                            # 🧠 Brain
│   ├── engine.py                    # Execution engine & workflow controller
│   ├── scheduler.py                 # Task scheduling & concurrency
│   └── decision.py                  # Smart decision engine
│
├── modules/                         # 🔧 Scan Modules
│   ├── recon/                       # Reconnaissance
│   │   ├── subdomains.py            #   Subdomain enumeration
│   │   ├── hosts.py                 #   Live host detection
│   │   ├── asn.py                   #   ASN / IP range mapping
│   │   └── endpoints.py            #   Endpoint collection
│   ├── scanning/                    # Active Scanning
│   │   ├── ports.py                 #   Port scanning
│   │   ├── services.py              #   Service detection
│   │   ├── directories.py           #   Directory brute-force
│   │   └── fingerprint.py           #   Technology fingerprinting
│   ├── fuzzing/                     # Fuzzing Engine
│   │   ├── params.py                #   Parameter discovery
│   │   ├── endpoints.py             #   Hidden endpoint fuzzing
│   │   ├── wordlists.py             #   Wordlist management
│   │   └── payloads.py              #   246 curated payloads (9 categories)
│   └── vulns/                       # Vulnerability Detection (10 detectors)
│       ├── xss.py                   #   XSS (reflected + DOM)
│       ├── sqli.py                  #   SQL injection (error-based)
│       ├── ssti.py                  #   Server-Side Template Injection
│       ├── ssrf.py                  #   Server-Side Request Forgery
│       ├── nosqli.py                #   NoSQL injection (MongoDB)
│       ├── csrf.py                  #   Cross-Site Request Forgery
│       ├── cors.py                  #   CORS misconfiguration
│       ├── idor.py                  #   Insecure Direct Object Reference
│       ├── redirect.py              #   Open redirect
│       └── misconfig.py             #   Security headers & info disclosure
│
├── integrations/                    # 🔌 External Tools
│   ├── base.py                      # Abstract tool wrapper
│   ├── subfinder.py                 # subfinder integration
│   ├── httpx.py                     # httpx integration
│   ├── ffuf.py                      # ffuf integration
│   ├── nuclei.py                    # nuclei integration
│   └── interactsh.py                # OOB blind vuln detection
│
├── database/                        # 🗄️ Storage
│   ├── models.py                    # Data models
│   ├── manager.py                   # Async CRUD handler
│   └── schema.sql                   # SQLite schema
│
├── utils/                           # 🛠️ Utilities
│   ├── logger.py                    # Rich logging system
│   ├── validators.py                # Input validation
│   ├── network.py                   # Async HTTP client (with auth injection)
│   ├── auth.py                      # Authentication manager (cookie/JWT/auto-login)
│   ├── parsers.py                   # Output parsers
│   └── helpers.py                   # General helpers
│
├── cli/                             # 💻 CLI
│   └── interface.py                 # Argument parsing
│
├── reports/                         # 📊 Reporting
│   ├── generator.py                 # Report engine
│   ├── templates/report.html        # HTML template
│   └── sample_output.json           # Sample output
│
└── data/                            # 📁 Data
    └── wordlists/                   # Built-in wordlists
        ├── common_subdomains.txt    #   ~100 subdomain prefixes
        ├── common_dirs.txt          #   ~100 directory paths
        └── common_params.txt        #   ~100 parameter names
```

---

## ⚡ Quick Start

### Prerequisites

- Python 3.10+ (recommended: 3.13+)
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/HexHunterX.git
cd HexHunterX

# Install dependencies
pip install -r requirements.txt
```

### Run Your First Scan

```bash
# Full scan against a domain (all 5 phases)
python main.py -t example.com --full-scan
```

### Optional: External Tools

For enhanced capabilities, install these tools (HexHunterX works without them):

```bash
# ProjectDiscovery tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# ffuf
go install github.com/ffuf/ffuf/v2@latest
```

> These are **optional**. HexHunterX falls back to built-in Python implementations when external tools are not available.

---

## 🚀 Usage Guide

### 1. Full Scan (All Phases)

Runs the complete pipeline: Recon → Scanning → Fuzzing → Vulnerability Checks → Report.

```bash
python main.py -t example.com --full-scan
```

This will:
1. Enumerate subdomains (passive + brute-force)
2. Probe for alive hosts
3. Scan open ports and fingerprint technologies
4. Discover hidden parameters and endpoints
5. Run all **10 vulnerability detectors** against every discovered endpoint
6. Generate JSON + HTML reports in `reports/output/`

---

### 2. Individual Phases

Run only the phases you need:

```bash
# Reconnaissance only (subdomains, hosts, endpoints)
python main.py -t example.com --recon

# Recon + Scanning (ports, directories, tech fingerprint)
python main.py -t example.com --recon --scan

# Fuzzing only (parameter discovery, endpoint fuzzing)
python main.py -t example.com --fuzz

# Vulnerability checks only (runs all 10 detectors)
python main.py -t example.com --vuln

# Combine any phases
python main.py -t example.com --recon --vuln
```

> **Note:** A report is **always generated automatically** after the selected phases complete.

---

### 3. Target Types

HexHunterX accepts multiple target formats:

```bash
# Domain
python main.py -t example.com --full-scan

# Subdomain
python main.py -t api.example.com --vuln

# URL (scans the specific page)
python main.py -t https://example.com/login --vuln

# IP address
python main.py -t 192.168.1.100 --scan

# CIDR range
python main.py -t 192.168.1.0/24 --scan --threads 200
```

---

### 4. Performance Tuning

Control speed and concurrency:

```bash
# High-speed scan (200 threads, 50 req/s)
python main.py -t example.com --full-scan --threads 200 --rate-limit 50

# Stealth mode (slow and quiet, 2 threads, 1 req/s)
python main.py -t example.com --full-scan --threads 2 --rate-limit 1

# Increase HTTP timeout for slow targets
python main.py -t slow-target.com --full-scan --timeout 30
```

| Flag | Default | Description |
|------|---------|-------------|
| `--threads N` | 50 | Number of concurrent async tasks |
| `--rate-limit N` | 10 | Maximum HTTP requests per second |
| `--timeout N` | 10 | HTTP request timeout in seconds |

---

### 5. Resume an Interrupted Scan

If a scan is interrupted (Ctrl+C, crash, network issue), resume where you left off:

```bash
python main.py -t example.com --full-scan --resume
```

This skips any phase that already has data in the database, saving time and bandwidth.

---

### 6. Custom Configuration

Use a custom YAML config file for different engagement profiles:

```bash
python main.py -t example.com --full-scan --config config/aggressive.yaml
```

Or edit the default config at `config/default.yaml`:

```yaml
general:
  threads: 50            # Concurrent async tasks
  timeout: 10            # HTTP timeout (seconds)
  rate_limit: 10         # Requests per second
  max_retries: 3         # Retry failed requests
  user_agent: "HexHunterX/1.0 (Security Assessment)"
  verify_ssl: false      # Skip SSL certificate validation

recon:
  passive_sources:       # Passive subdomain sources
    - crt_sh
    - hackertarget
  subdomain_wordlist: "data/wordlists/common_subdomains.txt"
  enable_bruteforce: true
  enable_permutations: true
  enable_wayback: true   # Query Wayback Machine for endpoints

scanning:
  top_ports: 35          # Number of top ports to scan
  dir_wordlist: "data/wordlists/common_dirs.txt"
  extensions: ["", ".php", ".html", ".js", ".json", ".txt", ".xml", ".asp", ".aspx", ".jsp"]
  fingerprint: true      # Enable technology fingerprinting

fuzzing:
  param_wordlist: "data/wordlists/common_params.txt"
  max_depth: 3           # Fuzzing recursion depth
  max_params_per_url: 200
  enable_api_fuzzing: true
  backup_extensions: [".bak", ".old", ".orig", ".save", ".swp"]

vulnerability:
  checks: [xss, sqli, open_redirect, idor, misconfig]
  max_urls_per_check: 20
  xss_payloads_per_param: 5
  sqli_payloads_per_param: 5
  verify_findings: true  # Validate findings to reduce false positives

reporting:
  format: [json, html]
  output_dir: "reports/output"
  include_evidence: true
  include_reproduction: true

integrations:
  subfinder:
    enabled: true
    timeout: 120
  httpx:
    enabled: true
    threads: 50
  ffuf:
    enabled: true
    threads: 40
  nuclei:
    enabled: true
    severity: "low,medium,high,critical"
    rate_limit: 150
```

---

### 7. Report Output

```bash
# Default: JSON + HTML in reports/output/
python main.py -t example.com --full-scan

# Custom output directory
python main.py -t example.com --full-scan --output reports/client_x

# JSON only
python main.py -t example.com --full-scan --format json

# HTML only
python main.py -t example.com --full-scan --format html
```

Reports are saved to the output directory:
- **`report.json`** -- Machine-readable structured findings for CI/CD pipelines
- **`report.html`** -- Professional dark-themed report with severity cards, expandable evidence, and reproduction steps

---

### 8. Scope Control

Limit or exclude targets during a scan:

```bash
# Only scan targets listed in scope file
python main.py -t example.com --full-scan --scope-file scope.txt

# Exclude specific targets
python main.py -t example.com --full-scan --exclude-file exclude.txt
```

**scope.txt** / **exclude.txt** format (one target per line):
```
*.example.com
api.example.com
192.168.1.0/24
```

---

### 9. Database Management

HexHunterX stores all results in SQLite for persistence:

```bash
# Use custom database file
python main.py -t example.com --full-scan --db client_scan.db

# Resume from a specific database
python main.py -t example.com --full-scan --resume --db client_scan.db
```

---

### 10. Silent / Headless Mode

For CI/CD pipelines or scripted workflows:

```bash
python main.py -t example.com --full-scan --silent --format json --output results/
```

The `--silent` flag suppresses the ASCII banner and non-essential console output.

---

## 🔎 Vulnerability Detectors (10 Modules)

Every detector runs automatically during the `--vuln` phase and produces findings with full evidence, reproduction steps, and confidence ratings.

### XSS (Cross-Site Scripting)
- Injects canary strings into parameters to detect reflection
- Determines context (HTML body, attribute, script block, comment)
- Sends context-appropriate payloads (42 payloads)
- Detects DOM-based XSS via source-sink pattern analysis

### SQLi (SQL Injection)
- Error-based detection with 54 payloads
- Multi-database support: MySQL, PostgreSQL, MSSQL, Oracle, SQLite
- Time-based blind SQLi detection (SLEEP, WAITFOR DELAY, pg_sleep)
- WAF bypass techniques (comment injection, case mixing, inline comments)

### SSTI (Server-Side Template Injection)
- Injects arithmetic probes: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`
- Detects computed values (e.g. `49`) in response
- Identifies template engine: Jinja2, Twig, FreeMarker, ERB, Thymeleaf
- Severity: **Critical** (leads to Remote Code Execution)

### SSRF (Server-Side Request Forgery)
- Tests 38 payloads: AWS/GCP/Azure cloud metadata, localhost IP bypasses
- Protocol smuggling: `file://`, `gopher://`, `dict://`
- Detects internal data leakage via metadata keyword matching
- Blind SSRF detection via response timing anomalies

### NoSQLi (NoSQL Injection)
- MongoDB operator injection: `$ne`, `$gt`, `$regex`, `$exists`, `$in`
- Tests both URL parameters (`param[$ne]=`) and JSON POST bodies
- Auth bypass detection via response status/size analysis
- 18 curated payloads for MongoDB and CouchDB

### CSRF (Cross-Site Request Forgery)
- Parses HTML forms and checks for missing CSRF token fields
- Validates against 15+ known token field names (csrf_token, _csrf, authenticity_token, etc.)
- Analyses `SameSite` cookie attribute on session cookies
- Generates auto-submit HTML PoC forms for vulnerable endpoints

### CORS (Cross-Origin Resource Sharing Misconfiguration)
- Tests multiple malicious `Origin` headers: evil domain, null, subdomain suffix/prefix match
- Checks `Access-Control-Allow-Credentials: true` for credential theft risk
- Severity: **Critical** if origin reflected + credentials allowed
- Generates JavaScript exploitation PoC snippets

### IDOR (Insecure Direct Object Reference)
- Identifies numeric/sequential ID parameters
- Tests adjacent IDs (id-1, id+1, id+100)
- Compares response size and content to detect different objects returned
- Detects path-based patterns (`/users/123`)

### Open Redirect
- Tests 28 redirect payloads against common parameter names (url, redirect, next, return, etc.)
- Inspects `Location` header without following redirects
- Detects client-side redirects (meta refresh, `window.location`)

### Misconfiguration & Security Headers
- Checks 7 security headers: HSTS, X-Content-Type-Options, X-Frame-Options, CSP, X-XSS-Protection, Referrer-Policy, Permissions-Policy
- Detects information disclosure: `X-Powered-By`, `Server`, `X-AspNet-Version`
- Basic CORS wildcard detection

---

## 📊 Sample Output

### Console Output

```
    ██╗  ██╗███████╗██╗  ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
    ...
    Modular Penetration Testing Framework                    v1.0.0

  Target:  example.com
  Phases:  recon, scan, fuzz, vuln, report
  Resume:  No

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ▶ PHASE: RECON
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✓ [recon.subdomains] Found 42 subdomains
✓ [recon.hosts] 18/42 hosts alive

  [CRITICAL] SSTI (Jinja2 / Twig) → app.example.com
    ↳ Server-Side Template Injection in parameter 'name'
  [CRITICAL] SQL Injection → api.example.com
    ↳ Error-based SQLi in parameter 'id' (MySQL)
  [CRITICAL] SSRF (Data Leakage) → api.example.com
    ↳ Internal metadata leaked via parameter 'url'
  [HIGH] XSS (Reflected) → example.com
    ↳ Reflected XSS in parameter 'q'
  [MEDIUM] CORS Misconfiguration → api.example.com
    ↳ CORS reflects arbitrary origin
  [MEDIUM] CSRF (Missing Token) → example.com/settings
    ↳ Form without CSRF token

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ▶ SCAN SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Metric         Count
  Subdomains        42
  Endpoints        156
  Open Ports        12
  Vulnerabilities   11

  Vulnerability Breakdown:
    CRITICAL     →  3
    HIGH         →  2
    MEDIUM       →  4
    LOW          →  1
    INFO         →  1
```

---

## 🔌 Complete CLI Reference

| Flag | Description | Default |
|------|-------------|---------|
| **Required** | | |
| `-t, --target` | Target domain, IP, CIDR, or URL | *(required)* |
| **Scan Phases** | | |
| `--recon` | Run reconnaissance phase | off |
| `--scan` | Run scanning phase | off |
| `--fuzz` | Run fuzzing phase | off |
| `--vuln` | Run vulnerability checks (all 10 detectors) | off |
| `--full-scan` | Run all phases (recon → scan → fuzz → vuln → report) | off |
| **Configuration** | | |
| `--config PATH` | Path to YAML config file | `config/default.yaml` |
| `--threads N` | Concurrent async tasks | 50 |
| `--rate-limit N` | Max HTTP requests per second | 10 |
| `--timeout N` | HTTP request timeout in seconds | 10 |
| **Output** | | |
| `-o, --output PATH` | Report output directory | `reports/output` |
| `--format {json,html,both}` | Report format | `both` |
| `--silent` | Suppress banner and non-essential output | off |
| **Authentication** | | |
| `--cookie STRING` | Raw cookie header (e.g. `"session=abc; token=xyz"`) | none |
| `--auth-token STRING` | Bearer/JWT token for Authorization header | none |
| `--auth-header STRING` | Custom auth header (`"X-API-Key: sk_live_abc"`) | none |
| `--login-url URL` | Login form URL for auto-login | none |
| `--login-user STRING` | Username for auto-login | none |
| `--login-pass STRING` | Password for auto-login | none |
| **OOB Detection (Blind Vulns)** | | |
| `--oob` | Enable blind/OOB detection via Interactsh | off |
| `--oob-server URL` | Custom Interactsh server | `oast.pro` |
| `--oob-token STRING` | Auth token for private Interactsh server | none |
| `--oob-poll N` | OOB polling interval in seconds | 5 |
| `--oob-wait N` | Seconds to wait for late OOB callbacks | 30 |
| **Advanced** | | |
| `--resume` | Resume scan from database (skip completed phases) | off |
| `--db PATH` | SQLite database file path | `HexHunterX.db` |
| `--scope-file PATH` | File with in-scope targets (one per line) | none |
| `--exclude-file PATH` | File with out-of-scope targets (one per line) | none |

---

## 🗄️ Database Schema

HexHunterX uses SQLite for persistent storage:

| Table | Purpose |
|-------|---------|
| `targets` | Target domains, IPs, CIDRs with scope |
| `subdomains` | Discovered subdomains with probe results |
| `endpoints` | URLs, methods, parameters |
| `scan_results` | Open ports, services, banners |
| `vulnerabilities` | Findings with evidence and PoC |
| `logs` | Module activity logging |

---

## 🧠 Smart Decision Engine

HexHunterX's decision engine adapts scanning based on what it discovers:

| Detection | Action |
|-----------|--------|
| Login page found | Prioritize authentication testing |
| API endpoints detected | Enable API-specific fuzzing (BOLA, mass assignment) |
| High parameter count | Increase fuzzing depth |
| CMS detected | Run CMS-specific vulnerability checks |
| Admin panel found | Test default credentials and access control |
| File upload detected | Test unrestricted upload and path traversal |

---

## 🔧 Common Workflows

### Bug Bounty Recon

```bash
# Step 1: Discover the attack surface
python main.py -t target.com --recon

# Step 2: Scan and fingerprint alive hosts
python main.py -t target.com --scan --resume

# Step 3: Find hidden parameters and endpoints
python main.py -t target.com --fuzz --resume

# Step 4: Run all vulnerability detectors
python main.py -t target.com --vuln --resume
```

### Authenticated Scan (Cookie-based)

```bash
python main.py -t example.com --full-scan --cookie "session=abc123; csrf=xyz"
```

### Authenticated Scan (Auto-Login)

```bash
python main.py -t example.com --full-scan \
  --login-url https://example.com/login \
  --login-user admin \
  --login-pass password123
```

### Authenticated Scan (JWT / API Key)

```bash
# JWT Bearer token
python main.py -t api.example.com --full-scan --auth-token "eyJhbGciOiJIUzI1NiIs..."

# Custom API key header
python main.py -t api.example.com --full-scan --auth-header "X-API-Key: sk_live_abc123"
```

### Blind Vulnerability Detection (OOB)

```bash
# Enable Interactsh for blind SSRF, blind SQLi, blind SSTI, stored XSS
python main.py -t example.com --full-scan --oob

# Use a private Interactsh server with longer wait time
python main.py -t example.com --full-scan --oob --oob-server interact.mydomain.com --oob-wait 60
```

### Combined: Auth + Blind Detection

```bash
python main.py -t example.com --full-scan \
  --cookie "session=abc123" \
  --oob --oob-wait 60
```

### Quick Vulnerability Check on a Single Page

```bash
python main.py -t https://target.com/search?q=test --vuln
```

### Stealth Engagement (Low & Slow)

```bash
python main.py -t target.com --full-scan --threads 2 --rate-limit 1 --timeout 30
```

### CI/CD Pipeline Integration

```bash
python main.py -t staging.company.com --full-scan --silent --format json --output ci-results/
# Then parse ci-results/report.json in your pipeline
```

### Resume After Interruption

```bash
# Scan gets interrupted...
python main.py -t target.com --full-scan

# Resume later -- skips completed phases automatically
python main.py -t target.com --full-scan --resume
```

---

## 🚧 Future Improvements

- [x] ~~Authenticated scanning (Cookie/JWT session support)~~ ✅ Implemented
- [x] ~~Blind/OOB vulnerability detection~~ ✅ Implemented (Interactsh)
- [ ] Web-based dashboard (Flask/FastAPI)
- [ ] Plugin architecture for custom modules
- [ ] Multi-target campaign management
- [ ] Active exploitation module (with safeguards)
- [ ] API key management for premium OSINT sources
- [ ] Docker containerization
- [ ] WebSocket support for real-time updates
- [ ] Machine learning-based false positive reduction
- [ ] Custom Nuclei template generation
- [ ] Collaboration features (team sharing, comments)
- [ ] Burp Suite/ZAP integration
- [ ] Headless browser engine for DOM XSS verification

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-module`)
3. Follow PEP 8 style guidelines
4. Add tests for new functionality
5. Submit a pull request

---

## 📝 License

This project is licensed under the MIT License -- see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Legal Disclaimer

**HexHunterX is designed for authorized security testing only.**

- Always obtain written permission before scanning any target
- Never use this tool against systems you don't own or have explicit authorization to test
- The authors are not responsible for any misuse or damage caused by this tool
- Comply with all applicable local, state, national, and international laws

---

<div align="center">
<p><strong>Built with ⚡ by the HexHunterX Team</strong></p>
<p><em>If you find this tool useful, please ⭐ the repository!</em></p>
</div>
