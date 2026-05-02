"""
HexHunterX -- XSS Detection Module (v2).

Professional-grade reflected and DOM-based XSS detection with:
- Context-aware reflection analysis
- Sanitization / encoding detection
- Execution feasibility verification
- DOM source-to-sink taint analysis
- Multi-tier confidence scoring
- No parameter invention
"""

import re
from urllib.parse import urlencode, urlparse, parse_qs

from utils.logger import HexHunterXLogger
from utils.network import AsyncHTTPClient
from modules.fuzzing.payloads import PayloadEngine
from modules.vulns.verification import (
    ResponseAnalyzer, ConfidenceScorer, Confidence,
)

logger = HexHunterXLogger.get_logger("vulns.xss")

# Encoding patterns for sanitization detection
_ENCODED = {
    "<": ["&lt;", "&#60;", "&#x3c;", "%3C", "%3c"],
    ">": ["&gt;", "&#62;", "&#x3e;", "%3E", "%3e"],
    '"': ["&quot;", "&#34;", "&#x22;", "%22"],
    "'": ["&#39;", "&#x27;", "%27"],
}


class XSSDetector:
    """
    Detect reflected and DOM-based XSS with real verification.

    Methodology:
        1. Inject canary in each EXISTING parameter
        2. Determine exact reflection context
        3. Check if critical characters survive un-encoded
        4. Test context-appropriate payloads (max 3)
        5. Verify payload lands in executable position
        6. Score confidence based on multiple signals
    """

    CANARY = "hxhx5s"

    def __init__(self, http_client: AsyncHTTPClient, oob_client=None):
        self.http = http_client
        self.oob = oob_client
        self._scorer = ConfidenceScorer()

    async def detect(self, url: str) -> list[dict]:
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return findings

        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param_name in params:
            finding = await self._test_param(base, param_name, params)
            if finding:
                findings.append(finding)

        dom_findings = await self._check_dom_xss(url)
        findings.extend(dom_findings)

        if self.oob and self.oob.is_registered:
            for param_name in params:
                for p in self.oob.get_oob_payloads("xss", base, param_name):
                    await self.http.get(f"{base}?{urlencode({param_name: p})}")

        return findings

    async def _test_param(self, base, param_name, all_params):
        canary = f"{self.CANARY}{param_name[:4]}"
        tp = {k: (v[0] if isinstance(v, list) else v) for k, v in all_params.items()}
        tp[param_name] = canary
        resp = await self.http.get(f"{base}?{urlencode(tp)}")
        if resp.error or canary not in resp.body:
            return None

        context = self._get_context(resp.body, canary)
        if context in ("comment", "textarea", "noscript", "none"):
            return None

        survived = await self._chars_survive(base, param_name, tp, context)
        if not survived:
            return None

        for payload in self._payloads_for(context)[:3]:
            tp[param_name] = payload
            pr = await self.http.get(f"{base}?{urlencode(tp)}")
            if pr.error:
                continue
            v = self._verify_exec(payload, pr.body, context)
            if v["ok"]:
                conf = self._scorer.score({
                    "reflection_in_executable_context": v["exec_ctx"],
                    "sanitization_absent": True,
                    "context_breakout": v["breakout"],
                    "baseline_differs": True,
                })
                sev = "high" if conf in (Confidence.HIGH, Confidence.CONFIRMED) else "medium"
                poc = PayloadEngine.generate_poc("xss", base, param_name, payload)
                return {
                    "type": "XSS (Reflected)",
                    "severity": sev,
                    "title": f"Reflected XSS in parameter '{param_name}'",
                    "description": (
                        f"Parameter '{param_name}' reflects input in {context} context "
                        f"without sanitization. Payload verified in executable position."
                    ),
                    "evidence": (
                        f"Context: {context}\nPayload: {payload}\n"
                        f"Verification: {v['reason']}"
                    ),
                    "request": f"{base}?{urlencode(tp)}",
                    "response": pr.body[:2000],
                    "reproduction": poc,
                    "confidence": conf,
                    "verification_method": "context_aware_reflection_analysis",
                }
        return None

    def _get_context(self, body, canary):
        idx = body.find(canary)
        if idx == -1:
            return "none"
        before = body[max(0, idx - 500):idx]
        # textarea / noscript
        for tag in ("textarea", "noscript"):
            o = before.lower().rfind(f"<{tag}")
            c = before.lower().rfind(f"</{tag}>")
            if o > c:
                return tag
        # comment
        if before.rfind("<!--") > before.rfind("-->"):
            return "comment"
        # script block
        so = before.rfind("<script")
        sc = before.rfind("</script>")
        if so > sc:
            seg = before[so:]
            dq = seg.count('"') - seg.count('\\"')
            sq = seg.count("'") - seg.count("\\'")
            if dq % 2 == 1:
                return "script_dq"
            if sq % 2 == 1:
                return "script_sq"
            return "script_bare"
        # attribute
        if re.search(r'on\w+\s*=\s*"[^"]*$', before, re.I):
            return "event_handler"
        if re.search(r'=\s*"[^"]*$', before):
            return "attr_dq"
        if re.search(r"=\s*'[^']*$", before):
            return "attr_sq"
        if re.search(r'=\s*[^\s"\'<>][^\s<>]*$', before):
            return "attr_uq"
        return "html_body"

    async def _chars_survive(self, base, param, tp, ctx):
        chars_needed = {"html_body": '<>"', "attr_dq": '"', "attr_sq": "'",
                        "attr_uq": " <>", "script_dq": '";', "script_sq": "';",
                        "script_bare": "</", "event_handler": '";'}
        chars = chars_needed.get(ctx, '<>"')
        probe = f"{self.CANARY}CHK{chars}END"
        tp[param] = probe
        r = await self.http.get(f"{base}?{urlencode(tp)}")
        if r.error or f"{self.CANARY}CHK" not in r.body:
            return False
        idx = r.body.find(f"{self.CANARY}CHK")
        seg = r.body[idx:idx + len(probe) + 30]
        for ch in chars:
            if ch not in seg:
                return False
            encs = _ENCODED.get(ch, [])
            if any(e in seg for e in encs):
                return False
        return True

    def _payloads_for(self, ctx):
        m = {
            "attr_dq": ['" onmouseover="alert(1)" x="',
                        '"><script>alert(1)</script>'],
            "attr_sq": ["' onmouseover='alert(1)' x='",
                        "'><script>alert(1)</script>"],
            "attr_uq": [" onmouseover=alert(1) ", " onfocus=alert(1) autofocus "],
            "script_dq": ['";alert(1);//', '";</script><script>alert(1)</script>'],
            "script_sq": ["';alert(1);//", "';</script><script>alert(1)</script>"],
            "script_bare": ["</script><script>alert(1)</script>", "-alert(1)-"],
            "event_handler": ['";alert(1);//', '"-alert(1)-"'],
        }
        return m.get(ctx, ['<script>alert(1)</script>',
                           '<img src=x onerror=alert(1)>',
                           '<svg/onload=alert(1)>'])

    def _verify_exec(self, payload, body, ctx):
        r = {"ok": False, "exec_ctx": False, "breakout": False, "reason": "Not found"}
        if payload not in body:
            return r
        idx = body.find(payload)
        before = body[max(0, idx - 500):idx]
        # Reject if inside comment/textarea/noscript
        for tag in ("<!--", "<textarea", "<noscript"):
            tag_open = before.lower().rfind(tag)
            close_tag = tag.replace("<", "</").replace("<!--", "-->")
            tag_close = before.lower().rfind(close_tag if tag != "<!--" else "-->")
            if tag_open > tag_close:
                r["reason"] = f"Inside {tag}"
                return r
        area = body[max(0, idx - 100):idx + len(payload) + 100]
        pats = [
            (r'<script[^>]*>.*?alert', "Script tag exec"),
            (r'on\w+\s*=\s*["\']?[^"\']*alert', "Event handler exec"),
            (r'<img[^>]*onerror\s*=', "IMG onerror"),
            (r'<svg[^>]*onload\s*=', "SVG onload"),
        ]
        for pat, desc in pats:
            if re.search(pat, area, re.I | re.DOTALL):
                r.update(ok=True, exec_ctx=True, reason=desc)
                break
        if ctx.startswith("attr") and re.search(r'["\'][^"\']*on\w+\s*=', area, re.I):
            r.update(ok=True, breakout=True, reason="Attribute breakout")
        if ctx.startswith("script") and re.search(r'["\'];.*?alert|</script>', area, re.I):
            r.update(ok=True, breakout=True, reason="JS string breakout")
        return r

    async def _check_dom_xss(self, url):
        findings = []
        resp = await self.http.get(url)
        if resp.error or resp.status_code != 200:
            return findings
        scripts = re.findall(r'<script[^>]*>(.*?)</script>', resp.body, re.DOTALL | re.I)
        if not scripts:
            return findings
        sources = {"location.hash": r'location\.hash', "location.search": r'location\.search',
                    "location.href": r'location\.href', "document.URL": r'document\.URL',
                    "document.referrer": r'document\.referrer', "window.name": r'window\.name'}
        sinks = {"innerHTML": r'\.innerHTML\s*=', "document.write": r'document\.write\s*\(',
                 "eval": r'(?<!\w)eval\s*\(', "outerHTML": r'\.outerHTML\s*='}
        flows = []
        for sc in scripts:
            s = [n for n, p in sources.items() if re.search(p, sc)]
            k = [n for n, p in sinks.items() if re.search(p, sc)]
            if s and k:
                flows.append({"sources": s, "sinks": k})
        if flows:
            desc = "; ".join(f"{','.join(f['sources'])}→{','.join(f['sinks'])}" for f in flows[:3])
            findings.append({
                "type": "XSS (DOM-based, Potential)",
                "severity": "medium",
                "title": "Potential DOM XSS — source-to-sink flow detected",
                "description": f"Source-to-sink flows in same script block: {desc}. Manual verification required.",
                "evidence": f"Flows: {flows}",
                "request": url, "response": "",
                "confidence": Confidence.LOW,
                "verification_method": "dom_taint_analysis",
            })
        return findings
