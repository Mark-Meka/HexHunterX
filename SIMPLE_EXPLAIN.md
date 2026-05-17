# HexHunterX: Simple Project Explanation

This document provides a simple, high-level breakdown of **HexHunterX** so you can easily explain how it works during discussions, interviews, or university presentations.

---

## What is HexHunterX?
HexHunterX is an automated **AI-Enhanced Web Penetration Testing Framework**. 
Think of it as a virtual security engineer. Instead of manually searching for vulnerabilities, HexHunterX automatically crawls a website, maps out its structure, throws thousands of smart test payloads at it, and then uses **Artificial Intelligence** to analyze the results and write a professional security report.

---

## The 4 Main Phases (How It Works)

When you run a scan on a target (like `example.com`), HexHunterX goes through four automated phases:

### Phase 1: Reconnaissance (Information Gathering)
Before attacking, the framework builds a map of the target.
- **Subdomain Discovery:** Finds hidden websites (e.g., `dev.example.com`).
- **Endpoint Crawling:** Clicks every link, analyzes Javascript files, and guesses hidden API routes (like `/rest/user/login`) to find every possible page on the site.
- **Port Scanning:** Checks which network ports are open.

### Phase 2: Scanning & Fuzzing
Once the map is built, it tries to find hidden files and test input fields.
- **Directory Brute-forcing:** Guesses hidden files (e.g., `admin.php`, `.env`).
- **Smart Fuzzing:** It finds every input field (search bars, login forms, JSON API bodies) and injects test payloads. It’s "smart" because it only tests relevant payloads (e.g., sending JSON payloads to JSON endpoints).

### Phase 3: Vulnerability Detection (The Attacks)
HexHunterX tests for the most critical web vulnerabilities (OWASP Top 10):
- **SQL Injection (SQLi)**: Tests if it can steal database info (supports both URL and JSON POST injection).
- **Cross-Site Scripting (XSS)**: Checks if it can inject malicious Javascript.
- **NoSQL & Auth Bypasses**: Tries to bypass login screens using advanced NoSQL operators.
- **SSRF & Out-of-Band (OOB)**: Uses external "Interactsh" servers to catch "blind" vulnerabilities that don't reflect on the screen.
- **IDOR, CSRF, CORS, SSTI, Open Redirects**: Tests for missing access controls and misconfigurations.

### Phase 4: AI Triage & Reporting
This is what makes HexHunterX unique compared to older scanners.
- **AI False Positive Filter**: Scanners usually generate a lot of false alarms. HexHunterX sends every detected vulnerability to an AI model (like Google's Gemma). The AI acts like a senior security engineer, analyzing the HTTP response to confirm if it's a real threat or a false positive.
- **AI Explanations**: The AI generates a detailed technical explanation of the vulnerability and exactly how the developers should fix it.
- **Standardized Evidence**: Every real vulnerability gets a professional 4-part evidence block:
  1. *Where Tested* (The URL)
  2. *How Tested* (The methodology)
  3. *Payload Used* (The exact injection string)
  4. *Verification Output* (The proof, like a database error or status flip)

Finally, it outputs all this data into beautiful **HTML and JSON Reports**.

---

## 3 Cool Features to Highlight in Discussions

1. **State Resilience (SQLite Database)**
   HexHunterX saves every single action into a local `.db` file. If your internet dies or the scan crashes, you can restart it with the `--resume` flag and it will pick up exactly where it left off.
2. **AI-Powered Context**
   Most scanners just say "XSS Found". HexHunterX says "XSS Found" and the AI explains *why* it's dangerous for this specific application and writes a custom remediation guide.
3. **Smart SPA API Fuzzing**
   Modern Single Page Applications (like Angular or React) hide their backend APIs. HexHunterX has built-in smart guessing to uncover hidden API routes (like `/api/v1/auth`) and dynamically injects SQL payloads directly into JSON POST bodies, a feature many traditional scanners lack.
