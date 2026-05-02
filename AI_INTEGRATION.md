# HexHunterX -- AI Integration Deep Dive

HexHunterX now includes a powerful, opt-in AI Analysis layer powered by the OpenRouter API (using `anthropic/claude-sonnet-4-5` by default). This transforms HexHunterX from a purely signature-based scanner into an intelligent "senior pentester" that can reason about context, detect statistical anomalies, filter false positives, and write executive reports.

---

## 🤖 What the AI Does

The AI integration operates across four key areas of the penetration testing lifecycle:

1. **Statistical Anomaly Detection:** Passively monitors HTTP responses to detect unusual behavior (e.g., a WAF blocking a request, or a backend struggling under load) using rolling baselines.
2. **Context-Aware Payload Generation:** If HexHunterX detects a specific tech stack (e.g., React + Express) or WAF, the AI generates highly targeted, evasion-focused payloads tailored specifically to that environment.
3. **False Positive Triage:** Before any vulnerability is saved to the database, the AI acts as a human analyst, examining the raw HTTP request, response snippet, and payload to determine if it's a true vulnerability or a generic error/coincidental reflection.
4. **Executive Reporting:** After the scan concludes, the AI analyzes the entire list of confirmed findings to write a concise executive summary, construct a realistic attack chain, and prioritize remediation efforts.

---

## 🛠️ How It Works Under the Hood

All AI features are located in the `ai/` directory and are strictly opt-in via the `--ai` CLI flags. The system is designed to **degrade gracefully** -- if the AI API is unreachable or the API key is missing, HexHunterX will log a warning and continue the scan normally without crashing.

### 1. `ai/client.py` (The OpenRouter Wrapper)
This is the core communication layer. It provides both synchronous (`requests`) and asynchronous (`httpx`) methods to call the OpenRouter API. It handles authentication via the `OPENROUTER_API_KEY` environment variable or the `--ai-key` CLI flag, and manages timeouts and API errors safely.

### 2. `ai/anomaly.py` (Statistical Anomaly Detection)
Wired directly into `utils/network.py`.
- **How it works:** It uses Python's built-in `statistics` module to maintain a rolling queue of recent HTTP response times and sizes.
- **The trigger:** If a new response deviates by more than 2 standard deviations from the rolling mean (after a minimum of 10 requests to establish a baseline), it is flagged as anomalous.
- **Why it matters:** This helps discover hidden rate limits, WAF drop policies, or computationally expensive endpoints (potential DoS vectors) without relying on signature matching.

### 3. `ai/payloads.py` (Context-Aware Payloads)
Wired into the `PayloadEngine` (`modules/fuzzing/payloads.py`).
- **How it works:** When the fuzzing or vulnerability modules request payloads for a specific category (e.g., `sqli`), the engine checks if the target's tech stack or WAF was identified during the scanning phase.
- **The trigger:** If context is available, a prompt is sent to the AI: *"Generate 10 highly optimized, evasion-focused payloads for SQLi, tailored exactly to MySQL and Cloudflare WAF."*
- **Why it matters:** These AI-generated payloads are prepended to the standard wordlists, significantly increasing the chances of bypassing modern defenses.

### 4. `ai/triage.py` (False Positive Filter)
Wired into the core execution engine (`core/engine.py`).
- **How it works:** After the standard vulnerability detectors finish but *before* findings are inserted into the database, each finding is passed to the AI Triage module.
- **The trigger:** The AI is provided with the vulnerability type, the payload used, the raw HTTP request, and a snippet of the raw HTTP response. It is prompted to respond with a strict JSON object containing a `verdict` (TRUE_POSITIVE or FALSE_POSITIVE), a `confidence` level, a brief `reasoning`, and a `recommendation`.
- **Why it matters:** This drastically reduces the noise typically associated with automated scanners by catching edge cases (like a WAF's 403 page reflecting the payload safely).

### 5. `ai/report_writer.py` (Executive Summary Generation)
Wired into the Report Generator (`reports/generator.py`).
- **How it works:** During the report generation phase, all confirmed vulnerabilities are aggregated and sent to the AI.
- **The trigger:** The AI is prompted to act as a Principal Security Consultant and return a JSON object containing a 3-sentence executive summary, a critical attack chain describing how the findings could be combined, and a list of the top 3 remediation priorities.
- **Why it matters:** It provides instant, high-level business context for stakeholders, making the final HTML report immediately actionable.

---

## 🚀 Enabling AI Features

You must provide an OpenRouter API key. You can do this via an environment variable:
```bash
export OPENROUTER_API_KEY="your-openrouter-key"
```

Or pass it directly via the CLI:
```bash
python main.py -t example.com --full-scan --ai --ai-key "your-openrouter-key"
```

### Granular Control
You don't have to enable everything. You can pick and choose which AI features to use:
- `--ai` : Enables all AI features.
- `--ai-triage` : Enables only the false positive filtering.
- `--ai-report` : Enables only the executive report generation.
- `--ai-payloads` : Enables only the context-aware payload generation.
