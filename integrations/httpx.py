"""
HexHunter -- HTTPX Integration.

Wraps ProjectDiscovery's httpx for HTTP probing and tech detection.
"""

from integrations.base import BaseToolWrapper
from utils.parsers import parse_json_output


class HTTPXWrapper(BaseToolWrapper):
    """Wrapper for httpx HTTP probing tool."""

    @property
    def tool_name(self) -> str:
        return "httpx"

    def build_command(self, targets_file: str = "", **kwargs) -> list[str]:
        args = ["-l", targets_file, "-json", "-silent",
                "-status-code", "-title", "-tech-detect", "-follow-redirects"]
        if kwargs.get("threads"):
            args.extend(["-threads", str(kwargs["threads"])])
        if kwargs.get("timeout"):
            args.extend(["-timeout", str(kwargs["timeout"])])
        return args

    def parse_output(self, stdout: str) -> list[dict]:
        entries = parse_json_output(stdout)
        results = []
        for entry in entries:
            results.append({
                "url": entry.get("url", ""),
                "status_code": entry.get("status_code", 0),
                "title": entry.get("title", ""),
                "tech": entry.get("tech", []),
                "content_length": entry.get("content_length", 0),
                "host": entry.get("host", ""),
                "ip": entry.get("a", [""])[0] if entry.get("a") else "",
            })
        return results
