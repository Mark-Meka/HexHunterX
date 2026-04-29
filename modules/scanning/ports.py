"""
HexHunterX -- Port Scanner Module.

Async TCP port scanning with banner grabbing and service identification.
"""

import asyncio
import socket
from utils.logger import HexHunterXLogger

logger = HexHunterXLogger.get_logger("scanning.ports")

# Common service-to-port mappings
COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpc", 135: "msrpc", 139: "netbios",
    143: "imap", 443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http-proxy",
    8443: "https-alt", 8888: "http-alt", 9090: "web-proxy",
    27017: "mongodb", 11211: "memcached",
}

# Top 100 ports for quick scanning
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 6379, 8000, 8080,
    8443, 8888, 9090, 9200, 9300, 27017, 11211, 6443, 10250,
]


class PortScanner:
    """
    Async TCP port scanner with service identification.

    Features:
        - Concurrent TCP connect scanning
        - Banner grabbing for service fingerprinting
        - Common service identification
    """

    def __init__(self, ports: list[int] | None = None, timeout: float = 2.0,
                 max_concurrent: int = 100):
        self.ports = ports or TOP_PORTS
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)

    async def scan(self, target: str, ports: list[int] | None = None) -> list[dict]:
        """
        Scan target for open ports.

        Args:
            target: IP address or hostname
            ports: Specific ports to scan (overrides default)

        Returns:
            List of dicts with port, service, banner info
        """
        scan_ports = ports or self.ports
        logger.info(f"Scanning {len(scan_ports)} ports on {target}")

        results = []

        async def _scan_port(port):
            async with self.semaphore:
                return await self._check_port(target, port)

        gathered = await asyncio.gather(
            *[_scan_port(p) for p in scan_ports],
            return_exceptions=True
        )

        for result in gathered:
            if isinstance(result, dict) and result.get("open"):
                results.append(result)

        logger.success(f"Found {len(results)} open ports on {target}")
        return results

    async def _check_port(self, target: str, port: int) -> dict:
        """Check if a single port is open and grab banner."""
        result = {"port": port, "open": False, "service": None, "banner": None}

        try:
            fut = asyncio.open_connection(target, port)
            reader, writer = await asyncio.wait_for(fut, timeout=self.timeout)

            result["open"] = True
            result["service"] = COMMON_SERVICES.get(port, "unknown")

            # Try banner grabbing
            try:
                writer.write(b"\r\n")
                await writer.drain()
                banner = await asyncio.wait_for(reader.read(1024), timeout=2)
                if banner:
                    result["banner"] = banner.decode("utf-8", errors="replace").strip()[:500]
            except Exception:
                pass

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            pass

        return result
