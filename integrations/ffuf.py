"""
HexHunter -- FFUF Integration.

Wraps ffuf for web fuzzing operations.
"""

from integrations.base import BaseToolWrapper
from utils.parsers import parse_json_output


class FFUFWrapper(BaseToolWrapper):
    """Wrapper for ffuf web fuzzer."""

    @property
    def tool_name(self) -> str:
        return "ffuf"

    def build_command(self, url: str = "", wordlist: str = "", **kwargs) -> list[str]:
        args = ["-u", url, "-w", wordlist, "-o", "/dev/stdout", "-of", "json", "-s"]
        if kwargs.get("method"):
            args.extend(["-X", kwargs["method"]])
        if kwargs.get("filters"):
            for f_type, f_val in kwargs["filters"].items():
                args.extend([f"-f{f_type}", str(f_val)])
        if kwargs.get("matchers"):
            for m_type, m_val in kwargs["matchers"].items():
                args.extend([f"-m{m_type}", str(m_val)])
        if kwargs.get("threads"):
            args.extend(["-t", str(kwargs["threads"])])
        if kwargs.get("headers"):
            for h in kwargs["headers"]:
                args.extend(["-H", h])
        return args

    def parse_output(self, stdout: str) -> list[dict]:
        entries = parse_json_output(stdout)
        results = []
        # ffuf JSON output wraps results in a "results" key
        if entries and isinstance(entries[0], dict) and "results" in entries[0]:
            entries = entries[0]["results"]
        for entry in entries:
            results.append({
                "url": entry.get("url", ""),
                "status": entry.get("status", 0),
                "length": entry.get("length", 0),
                "words": entry.get("words", 0),
                "lines": entry.get("lines", 0),
                "input": entry.get("input", {}),
            })
        return results
