"""
HexHunterX -- Output Parsers.

Parse JSON, XML, and text outputs from external tools into unified schema.
"""

import json
import re
from typing import Any


def parse_json_output(raw: str) -> list[dict]:
    """Parse JSON or JSONL output from external tools."""
    results = []
    raw = raw.strip()
    if not raw:
        return results

    # Try full JSON array
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return data
        return [data]
    except json.JSONDecodeError:
        pass

    # Try JSONL (one JSON object per line)
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return results


def parse_plain_list(raw: str) -> list[str]:
    """Parse newline-separated plain text output."""
    return [line.strip() for line in raw.splitlines() if line.strip()]


def extract_urls(text: str) -> list[str]:
    """Extract URLs from arbitrary text."""
    pattern = r'https?://[^\s<>"\'}\])]+'
    return list(set(re.findall(pattern, text)))


def extract_emails(text: str) -> list[str]:
    """Extract email addresses from text."""
    pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    return list(set(re.findall(pattern, text)))


def extract_ips(text: str) -> list[str]:
    """Extract IPv4 addresses from text."""
    pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    candidates = re.findall(pattern, text)
    valid = []
    for ip in candidates:
        parts = ip.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            valid.append(ip)
    return list(set(valid))


def parse_nmap_services(raw: str) -> list[dict]:
    """Parse nmap-style service output."""
    results = []
    for line in raw.splitlines():
        match = re.match(r'(\d+)/(tcp|udp)\s+(\w+)\s+(.*)', line)
        if match:
            results.append({
                "port": int(match.group(1)),
                "protocol": match.group(2),
                "state": match.group(3),
                "service": match.group(4).strip(),
            })
    return results


def normalize_severity(severity: str) -> str:
    """Normalize severity strings to standard values."""
    severity = severity.lower().strip()
    mapping = {
        "crit": "critical", "critical": "critical",
        "high": "high", "h": "high",
        "medium": "medium", "med": "medium", "m": "medium",
        "low": "low", "l": "low",
        "info": "info", "informational": "info", "i": "info",
    }
    return mapping.get(severity, "info")
