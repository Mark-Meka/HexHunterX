"""
HexHunterX -- Detector Accuracy Test (Local Mock Server)
==========================================================
Spins up a tiny Flask server locally that intentionally mimics
3 vulnerability scenarios, then runs HexHunterX detectors + AI
triage against them and reports accuracy results.

Scenarios:
  1. SQLi -- error-based (MySQL error in response)
  2. XSS  -- reflected (payload echoed unescaped into HTML)
  3. Clean -- safe endpoint (should produce 0 findings)
"""

import asyncio
import threading
import time
import yaml
from flask import Flask, request, Response

from utils.logger import console
from utils.network import AsyncHTTPClient
from ai.client import set_api_key, set_model, set_provider
from ai.triage import triage_finding
from modules.vulns.sqli import SQLiDetector
from modules.vulns.xss import XSSDetector

# ── Load AI config ────────────────────────────────────────────────────────────
with open("config/default.yaml", "r") as f:
    config = yaml.safe_load(f)

ai_cfg = config.get("ai", {})
AI_ENABLED = False
if ai_cfg.get("api_key"):
    set_api_key(ai_cfg["api_key"])
    set_model(ai_cfg.get("model", "gemma-3-27b-it"))
    set_provider(ai_cfg.get("provider", "google"))
    AI_ENABLED = True

# ── Mock Vulnerable Server ────────────────────────────────────────────────────
app = Flask("VulnMock")

@app.route("/sqli")
def sqli_endpoint():
    """Reflects MySQL error when quote char injected — error-based SQLi."""
    cat = request.args.get("cat", "")
    if "'" in cat or '"' in cat:
        body = (
            "<!DOCTYPE html><html><body>"
            "<p>Warning: mysqli_fetch_array() expects parameter 1 "
            f"to be mysqli_result.</p>"
            "<p>You have an error in your SQL syntax; check the manual that "
            f"corresponds to your MySQL server version for the right syntax "
            f"near &#039;{cat}&#039; at line 1</p>"
            "</body></html>"
        )
    else:
        body = (
            f"<!DOCTYPE html><html><body>"
            f"<h1>Products in category {cat}</h1>"
            f"<p>Widget A | Widget B | Widget C</p>"
            f"</body></html>"
        )
    return Response(body, content_type="text/html")


@app.route("/xss")
def xss_endpoint():
    """Reflects input directly into HTML — reflected XSS."""
    q = request.args.get("q", "")
    body = (
        f"<!DOCTYPE html><html><body>"
        f"<h1>Search Results for: {q}</h1>"
        f"<p>No results found.</p>"
        f"</body></html>"
    )
    return Response(body, content_type="text/html")


@app.route("/clean")
def clean_endpoint():
    """Safe endpoint — sanitizes all user input."""
    import html
    q = html.escape(request.args.get("q", ""))
    body = (
        f"<!DOCTYPE html><html><body>"
        f"<h1>Safe search: {q}</h1>"
        f"<p>Results would appear here.</p>"
        f"</body></html>"
    )
    return Response(body, content_type="text/html")


def start_server():
    import logging
    log = logging.getLogger("werkzeug")
    log.setLevel(logging.ERROR)
    app.run(port=18080, debug=False, use_reloader=False)


# ── Test Cases ────────────────────────────────────────────────────────────────
TEST_CASES = [
    {
        "name"      : "SQL Injection (Error-based)",
        "url"       : "http://127.0.0.1:18080/sqli?cat=1",
        "detector"  : "sqli",
        "expected"  : True,
    },
    {
        "name"      : "XSS (Reflected)",
        "url"       : "http://127.0.0.1:18080/xss?q=hello",
        "detector"  : "xss",
        "expected"  : True,
    },
    {
        "name"      : "Clean Endpoint (No Vuln)",
        "url"       : "http://127.0.0.1:18080/clean?q=hello",
        "detector"  : "xss",
        "expected"  : False,
    },
]

# ── Runner ────────────────────────────────────────────────────────────────────
async def run():
    console.print()
    console.print("[bold cyan]╔══════════════════════════════════════════╗[/bold cyan]")
    console.print("[bold cyan]║  HexHunterX Accuracy Test (Local Server)  ║[/bold cyan]")
    console.print("[bold cyan]╚══════════════════════════════════════════╝[/bold cyan]")
    console.print(f"\n  AI Model: [green]{ai_cfg.get('model','disabled')}[/green]" if AI_ENABLED else "\n  [yellow]AI disabled (no api_key)[/yellow]")
    console.print()

    # Start mock server in background thread
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()
    await asyncio.sleep(1.5)  # Let server start

    http = AsyncHTTPClient(timeout=10, max_connections=10)
    await http.start()

    results = []

    for tc in TEST_CASES:
        console.print(f"[bold white]━━━ {tc['name']} ━━━[/bold white]")
        console.print(f"  URL: {tc['url']}")
        console.print(f"  Expect finding: {'[green]Yes[/green]' if tc['expected'] else '[yellow]No[/yellow]'}")

        # ── Phase 1: Base Detector ────────────────────────────────────────
        t0 = time.time()
        if tc["detector"] == "sqli":
            detector = SQLiDetector(http)
        else:
            detector = XSSDetector(http)

        findings = await detector.detect(tc["url"])
        det_time = time.time() - t0

        found    = len(findings) > 0
        expected = tc["expected"]
        correct  = (found == expected)

        if found:
            console.print(
                f"  Base Detector: [green]Found {len(findings)} finding(s)[/green] "
                f"in {det_time:.1f}s — "
                f"{'[green]CORRECT ✓[/green]' if correct else '[red]WRONG ✗[/red]'}"
            )
            for f in findings[:2]:
                console.print(
                    f"    ↳ {f.get('type')} | "
                    f"Confidence: {f.get('confidence')} | "
                    f"{f.get('title','')}"
                )
        else:
            console.print(
                f"  Base Detector: [yellow]0 findings[/yellow] in {det_time:.1f}s — "
                f"{'[green]CORRECT ✓[/green]' if correct else '[red]FALSE NEGATIVE ✗[/red]'}"
            )

        # ── Phase 2: AI Triage ────────────────────────────────────────────
        ai_verdict = "SKIPPED"
        ai_correct = None

        if AI_ENABLED and found:
            console.print("  AI Triage: [yellow]analysing…[/yellow]")
            t1 = time.time()
            v = findings[0]
            triage = await triage_finding(
                vuln_type=v.get("type"),
                payload=v.get("evidence", ""),
                raw_request=v.get("request", ""),
                raw_response=v.get("response", ""),
            )
            triage_time = time.time() - t1
            ai_verdict = triage.get("verdict", "UNKNOWN")
            conf       = triage.get("confidence", "?")
            reason     = triage.get("reasoning", "")

            # For expected=True, correct AI verdict is TRUE_POSITIVE; for clean, FALSE_POSITIVE
            if expected:
                ai_correct = (ai_verdict == "TRUE_POSITIVE")
            else:
                ai_correct = (ai_verdict == "FALSE_POSITIVE")

            vcolor = "green" if ai_verdict == "TRUE_POSITIVE" else ("red" if ai_verdict == "FALSE_POSITIVE" else "yellow")
            console.print(
                f"  AI Verdict: [bold {vcolor}]{ai_verdict}[/bold {vcolor}] "
                f"(conf: {conf}) in {triage_time:.1f}s — "
                f"{'[green]CORRECT ✓[/green]' if ai_correct else '[red]WRONG ✗[/red]'}"
            )
            console.print(f"  AI Reason: {reason}")
        elif not AI_ENABLED:
            console.print("  AI Triage: [dim]disabled[/dim]")

        results.append({
            "name"       : tc["name"],
            "expected"   : expected,
            "found"      : found,
            "det_correct": correct,
            "ai_verdict" : ai_verdict,
            "ai_correct" : ai_correct,
        })
        console.print()

    await http.close()

    # ── Summary ───────────────────────────────────────────────────────────
    total     = len(results)
    det_score = sum(1 for r in results if r["det_correct"])
    ai_done   = [r for r in results if r["ai_correct"] is not None]
    ai_score  = sum(1 for r in ai_done if r["ai_correct"])

    console.print("[bold cyan]━━━ FINAL ACCURACY REPORT ━━━[/bold cyan]")
    console.print(f"  Test cases             : {total}")
    console.print(f"  Base Detector accuracy : [bold green]{det_score}/{total}[/bold green] ({det_score/total*100:.0f}%)")
    if ai_done:
        console.print(f"  AI Triage accuracy     : [bold green]{ai_score}/{len(ai_done)}[/bold green] ({ai_score/len(ai_done)*100:.0f}%)")
    else:
        console.print("  AI Triage accuracy     : [dim]N/A (no API key or no findings)[/dim]")

    console.print()
    # Per-test table
    for r in results:
        det_icon = "✓" if r["det_correct"] else "✗"
        ai_txt   = r["ai_verdict"] if r["ai_verdict"] != "SKIPPED" else "—"
        ai_icon  = ("✓" if r["ai_correct"] else "✗") if r["ai_correct"] is not None else "—"
        console.print(
            f"  {det_icon} {r['name']:<38} | "
            f"Detector: {'HIT' if r['found'] else 'MISS':<4} | "
            f"AI: {ai_txt:<16} {ai_icon}"
        )
    console.print()


if __name__ == "__main__":
    asyncio.run(run())
