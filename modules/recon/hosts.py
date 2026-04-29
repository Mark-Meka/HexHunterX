"""
HexHunter -- Live Host Detection Module.

HTTP/HTTPS probing to identify alive hosts with status, title, and IP resolution.
"""

import asyncio
import socket
from utils.logger import HexHunterLogger
from utils.network import AsyncHTTPClient

logger = HexHunterLogger.get_logger("recon.hosts")


class HostProber:
    """Probe subdomains to identify alive hosts via HTTP/HTTPS."""

    def __init__(self, http_client: AsyncHTTPClient):
        self.http = http_client

    async def probe_hosts(self, hostnames: list[str]) -> list[dict]:
        """
        Probe a list of hostnames for liveness.

        Returns list of dicts with host info: host, ip, status_code, title, scheme.
        """
        logger.info(f"Probing {len(hostnames)} hosts for liveness")
        sem = asyncio.Semaphore(30)
        results = []

        async def _probe(hostname):
            async with sem:
                return await self._probe_single(hostname)

        gathered = await asyncio.gather(*[_probe(h) for h in hostnames], return_exceptions=True)
        for r in gathered:
            if isinstance(r, dict) and r.get("alive"):
                results.append(r)

        logger.success(f"{len(results)}/{len(hostnames)} hosts alive")
        return results

    async def _probe_single(self, hostname: str) -> dict:
        """Probe a single hostname via HTTPS then HTTP fallback."""
        result = {"host": hostname, "alive": False, "ip": None,
                  "status_code": None, "title": None, "scheme": None}

        # Resolve IP
        try:
            loop = asyncio.get_event_loop()
            ip = await loop.run_in_executor(None, self._resolve_ip, hostname)
            result["ip"] = ip
        except Exception:
            pass

        # Try HTTPS first
        for scheme in ["https", "http"]:
            url = f"{scheme}://{hostname}"
            resp = await self.http.get(url, follow_redirects=True)

            if resp.status_code > 0 and not resp.error:
                result["alive"] = True
                result["status_code"] = resp.status_code
                result["scheme"] = scheme
                result["title"] = self._extract_title(resp.body)
                return result

        return result

    @staticmethod
    def _resolve_ip(hostname: str) -> str | None:
        """Resolve hostname to IP address."""
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None

    @staticmethod
    def _extract_title(html: str) -> str | None:
        """Extract page title from HTML."""
        import re
        match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()[:200]
        return None
