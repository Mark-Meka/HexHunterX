"""
HexHunter -- Subfinder Integration.

Wraps ProjectDiscovery's subfinder for passive subdomain enumeration.
"""

from integrations.base import BaseToolWrapper
from utils.parsers import parse_json_output, parse_plain_list


class SubfinderWrapper(BaseToolWrapper):
    """Wrapper for subfinder subdomain enumeration tool."""

    @property
    def tool_name(self) -> str:
        return "subfinder"

    def build_command(self, domain: str = "", **kwargs) -> list[str]:
        args = ["-d", domain, "-silent", "-json"]
        if kwargs.get("sources"):
            args.extend(["-sources", ",".join(kwargs["sources"])])
        if kwargs.get("timeout"):
            args.extend(["-timeout", str(kwargs["timeout"])])
        return args

    def parse_output(self, stdout: str) -> list[dict]:
        entries = parse_json_output(stdout)
        results = []
        for entry in entries:
            host = entry.get("host", "")
            if host:
                results.append({
                    "subdomain": host,
                    "source": entry.get("source", "subfinder"),
                    "ip": entry.get("ip", ""),
                })
        # Fallback to plain text
        if not results:
            for line in parse_plain_list(stdout):
                results.append({"subdomain": line, "source": "subfinder"})
        return results
