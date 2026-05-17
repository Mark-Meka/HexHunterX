"""
HexHunterX -- Report Generator.

Produces structured JSON and professional HTML reports from scan data.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from database.manager import DatabaseManager
from utils.logger import HexHunterXLogger
from utils.helpers import ensure_dir, save_json

logger = HexHunterXLogger.get_logger("reports")


class ReportGenerator:
    """
    Generate structured reports from scan results.

    Formats:
        - JSON: Machine-readable structured data
        - HTML: Professional human-readable report (Jinja2)
    """

    def __init__(self, db: DatabaseManager, config: dict):
        self.db = db
        self.config = config
        self.template_dir = Path(__file__).parent / "templates"

    async def generate(self, target_id: int, output_dir: str):
        """Generate all configured report formats."""
        output = ensure_dir(output_dir)

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
        target       = await self.db.get_target(target_id)
        subdomains   = await self.db.get_subdomains(target_id)
        vulns        = await self.db.get_vulnerabilities(target_id=target_id)
        scan_results = await self.db.get_scan_results(target_id)
        endpoints    = await self.db.get_all_endpoints_for_target(target_id)

        # Severity counts
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in vulns:
            sev = v.get("severity", "info").lower()
            if sev in sev_counts:
                sev_counts[sev] += 1

        # Read AI model from config for the meta block
        ai_model = (
            self.config.get("ai", {}).get("model", "N/A")
            if self.config.get("ai", {}).get("enabled") else "Disabled"
        )

        return {
            "meta": {
                "tool":         "HexHunterX",
                "version":      "1.0.0",
                "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                "scan_id":      target_id,
                "ai_model":     ai_model,
            },
            "target": target or {},
            "summary": {
                "total_subdomains":     len(subdomains),
                "alive_hosts":          len([s for s in subdomains if s.get("is_alive")]),
                "total_endpoints":      len(endpoints),
                "open_ports":           len(scan_results),
                "total_vulnerabilities": len(vulns),
                "severity_counts":      sev_counts,
            },
            "subdomains":   subdomains,
            "endpoints":    endpoints,
            "scan_results": scan_results,
            "vulnerabilities": vulns,
        }

    async def _generate_html(self, data: dict, output_path: Path):
        """Render HTML report using Jinja2 template."""
        if self.template_dir.exists():
            env = Environment(
                loader=FileSystemLoader(str(self.template_dir)),
                autoescape=select_autoescape(disabled_extensions=("html",)),
            )
            template = env.get_template("report.html")
            html = template.render(**data)
        else:
            # Fallback: minimal inline template
            from jinja2 import Template
            html = Template(self._minimal_template()).render(**data)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

    @staticmethod
    def _minimal_template() -> str:
        """Minimal fallback template if the template file is missing."""
        return """<!DOCTYPE html>
<html><head><title>HexHunterX Report</title></head>
<body style="font-family:sans-serif;max-width:1000px;margin:2rem auto">
<h1>HexHunterX Report</h1>
<p>Generated: {{ meta.generated_at }} | Target: {{ target.domain or 'N/A' }}</p>
<h2>Vulnerabilities ({{ summary.total_vulnerabilities }})</h2>
{% for v in vulnerabilities %}
<p>[{{ v.severity | upper }}] {{ v.title }}</p>
{% else %}
<p>No vulnerabilities found.</p>
{% endfor %}
</body></html>"""
