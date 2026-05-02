"""
HexHunterX -- Report Generator.

Produces structured JSON and professional HTML reports from scan data.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Template

from database.manager import DatabaseManager
from utils.logger import HexHunterXLogger
from utils.helpers import ensure_dir, save_json
# AI-ENHANCED
from ai.report_writer import generate_executive_summary

logger = HexHunterXLogger.get_logger("reports")


class ReportGenerator:
    """
    Generate structured reports from scan results.

    Formats:
        - JSON: Machine-readable structured data
        - HTML: Professional human-readable report
    """

    def __init__(self, db: DatabaseManager, config: dict):
        self.db = db
        self.config = config
        self.template_dir = Path(__file__).parent / "templates"

    async def generate(self, target_id: int, output_dir: str):
        """Generate all configured report formats."""
        output = ensure_dir(output_dir)

        # Gather data
        report_data = await self._gather_data(target_id)
        target_name = report_data.get("target", {}).get("domain", "unknown")

        formats = self.config.get("reporting", {}).get("format", ["json", "html"])

        if "json" in formats:
            json_path = output / f"HexHunterX_report_{target_name}.json"
            save_json(report_data, json_path)
            logger.success(f"JSON report: {json_path}")

        if "html" in formats:
            html_path = output / f"HexHunterX_report_{target_name}.html"
            await self._generate_html(report_data, html_path)
            logger.success(f"HTML report: {html_path}")

    async def _gather_data(self, target_id: int) -> dict:
        """Gather all scan data for the report."""
        target = await self.db.get_target(target_id)
        subdomains = await self.db.get_subdomains(target_id)
        vulns = await self.db.get_vulnerabilities(target_id=target_id)
        scan_results = await self.db.get_scan_results(target_id)
        stats = await self.db.get_stats(target_id)

        # Collect endpoints
        all_endpoints = await self.db.get_all_endpoints_for_target(target_id)

        # Severity counts
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in vulns:
            sev = v.get("severity", "info").lower()
            if sev in sev_counts:
                sev_counts[sev] += 1

        return {
            "meta": {
                "tool": "HexHunterX",
                "version": "1.0.0",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "scan_id": target_id,
            },
            "target": target or {},
            "summary": {
                "total_subdomains": len(subdomains),
                "alive_hosts": len([s for s in subdomains if s.get("is_alive")]),
                "total_endpoints": len(all_endpoints),
                "open_ports": len(scan_results),
                "total_vulnerabilities": len(vulns),
                "severity_counts": sev_counts,
            },
            "subdomains": subdomains,
            "endpoints": all_endpoints,
            "scan_results": scan_results,
            "vulnerabilities": vulns,
        }
        
        # AI-ENHANCED
        if self.config.get("ai_report"):
            logger.info("Generating AI Executive Summary...")
            ai_data = await generate_executive_summary(target_name, vulns)
            report_data["ai_analysis"] = ai_data

        return report_data

    async def _generate_html(self, data: dict, output_path: Path):
        """Generate HTML report using Jinja2 template."""
        template_path = self.template_dir / "report.html"

        if template_path.exists():
            template_str = template_path.read_text(encoding="utf-8")
        else:
            template_str = self._get_default_template()

        template = Template(template_str)
        html = template.render(**data)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

    @staticmethod
    def _get_default_template() -> str:
        """Fallback HTML template if template file not found."""
        return """<!DOCTYPE html>
<html><head><title>HexHunterX Report</title>
<style>
body { font-family: sans-serif; margin: 40px; background: #f5f5f5; color: #333; }
.card { background: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
.ai-card { background: #1e1e1e; color: #e0e0e0; padding: 20px; margin-bottom: 20px; border-radius: 8px; border-left: 5px solid #00ffcc; }
.ai-card h2 { color: #00ffcc; margin-top: 0; }
.vuln { padding: 10px; border-bottom: 1px solid #ddd; }
</style>
</head>
<body>
<h1>HexHunterX Scan Report</h1>
<p>Generated: {{ meta.generated_at }}</p>

{% if ai_analysis %}
<!-- AI-ENHANCED Section -->
<div class="ai-card">
    <h2>AI Executive Analysis</h2>
    <p><strong>Executive Summary:</strong> {{ ai_analysis.executive_summary }}</p>
    <p><strong>Critical Attack Chain:</strong> {{ ai_analysis.critical_attack_chain }}</p>
    <h3>Remediation Priorities</h3>
    <ul>
    {% for prio in ai_analysis.remediation_priorities %}
        <li><strong>{{ prio.title }}:</strong> {{ prio.reasoning }}</li>
    {% endfor %}
    </ul>
</div>
{% endif %}

<div class="card">
    <h2>Vulnerabilities ({{ summary.total_vulnerabilities }})</h2>
    {% for vuln in vulnerabilities %}
    <div class="vuln">
        <strong>[{{ vuln.severity | upper }}]</strong> {{ vuln.title }}
        {% if vuln.ai_triage %}
        <br><em>AI Triage: {{ vuln.ai_triage.verdict }} (Confidence: {{ vuln.ai_triage.confidence }})</em>
        {% endif %}
    </div>
    {% endfor %}
</div>
</body></html>"""
