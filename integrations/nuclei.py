"""
HexHunterX -- Nuclei Integration.

Wraps ProjectDiscovery's nuclei for template-based vulnerability scanning.
"""

from integrations.base import BaseToolWrapper
from utils.parsers import parse_json_output


class NucleiWrapper(BaseToolWrapper):
    """Wrapper for nuclei vulnerability scanner."""

    @property
    def tool_name(self) -> str:
        return "nuclei"

    def build_command(self, target: str = "", **kwargs) -> list[str]:
        args = ["-u", target, "-jsonl", "-silent"]
        if kwargs.get("templates"):
            args.extend(["-t", kwargs["templates"]])
        if kwargs.get("severity"):
            args.extend(["-severity", kwargs["severity"]])
        if kwargs.get("tags"):
            args.extend(["-tags", kwargs["tags"]])
        if kwargs.get("rate_limit"):
            args.extend(["-rl", str(kwargs["rate_limit"])])
        if kwargs.get("concurrency"):
            args.extend(["-c", str(kwargs["concurrency"])])
        return args

    def parse_output(self, stdout: str) -> list[dict]:
        entries = parse_json_output(stdout)
        results = []
        for entry in entries:
            info = entry.get("info", {})
            results.append({
                "template_id": entry.get("template-id", ""),
                "name": info.get("name", ""),
                "severity": info.get("severity", "info"),
                "description": info.get("description", ""),
                "matched_at": entry.get("matched-at", ""),
                "type": entry.get("type", ""),
                "host": entry.get("host", ""),
                "curl_command": entry.get("curl-command", ""),
                "tags": info.get("tags", []),
            })
        return results
