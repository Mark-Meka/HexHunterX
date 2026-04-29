"""
HexHunterX -- Service Detection Module.

Identify services from banners and responses.
"""

import re
from utils.logger import HexHunterXLogger

logger = HexHunterXLogger.get_logger("scanning.services")

# Banner-to-service patterns
SERVICE_PATTERNS = [
    (r"SSH-\d\.\d-OpenSSH[_ ](\S+)", "openssh", "ssh"),
    (r"SSH-\d\.\d-dropbear[_ ](\S+)", "dropbear", "ssh"),
    (r"220.*FTP", "ftp", "ftp"),
    (r"220.*vsFTPd (\S+)", "vsftpd", "ftp"),
    (r"220.*ProFTPD (\S+)", "proftpd", "ftp"),
    (r"MySQL|MariaDB", "mysql", "database"),
    (r"PostgreSQL", "postgresql", "database"),
    (r"redis_version:(\S+)", "redis", "cache"),
    (r"MongoDB", "mongodb", "database"),
    (r"Apache/(\S+)", "apache", "http"),
    (r"nginx/(\S+)", "nginx", "http"),
    (r"Microsoft-IIS/(\S+)", "iis", "http"),
    (r"Exim (\S+)", "exim", "smtp"),
    (r"Postfix", "postfix", "smtp"),
]


class ServiceDetector:
    """Identify services from scan banners."""

    @staticmethod
    def identify(banner: str, port: int = 0) -> dict:
        """
        Identify a service from its banner string.

        Returns dict with: product, version, type.
        """
        if not banner:
            return {"product": "unknown", "version": None, "type": "unknown"}

        for pattern, product, svc_type in SERVICE_PATTERNS:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex else None
                return {"product": product, "version": version, "type": svc_type}

        return {"product": "unknown", "version": None, "type": "unknown"}

    @staticmethod
    def from_headers(headers: dict) -> dict:
        """Identify service from HTTP response headers."""
        server = headers.get("Server", headers.get("server", ""))
        powered = headers.get("X-Powered-By", headers.get("x-powered-by", ""))

        return {
            "server": server,
            "powered_by": powered,
            "technologies": [t.strip() for t in [server, powered] if t],
        }
