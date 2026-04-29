"""
HexHunterX -- Hidden Endpoint Discovery Module.

Brute-force API paths, backup files, and hidden endpoints.
"""

import asyncio
from utils.logger import HexHunterXLogger
from utils.network import AsyncHTTPClient
from utils.helpers import load_wordlist

logger = HexHunterXLogger.get_logger("fuzzing.endpoints")

# Common API path patterns
API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/graphql", "/graphiql", "/playground",
    "/swagger", "/swagger.json", "/swagger-ui",
    "/openapi.json", "/api-docs", "/docs",
    "/health", "/healthcheck", "/status", "/metrics",
    "/debug", "/trace", "/info", "/env",
    "/.env", "/.git/HEAD", "/robots.txt", "/sitemap.xml",
    "/config.json", "/config.yaml", "/config.yml",
    "/backup", "/backup.sql", "/backup.zip",
    "/admin", "/console", "/dashboard",
    "/wp-admin", "/wp-login.php", "/wp-json/wp/v2/users",
]

BACKUP_EXTENSIONS = [".bak", ".old", ".orig", ".save", ".swp", ".tmp", "~"]


class EndpointFuzzer:
    """
    Discover hidden endpoints via brute-force.

    Techniques:
        - Common API path checking
        - Backup file detection
        - Custom wordlist fuzzing
    """

    def __init__(self, http_client: AsyncHTTPClient, config: dict):
        self.http = http_client
        self.config = config

    async def fuzz(self, base_url: str) -> list[str]:
        """
        Fuzz a target for hidden endpoints.

        Returns list of discovered URLs.
        """
        base = base_url.rstrip("/")
        found = []

        # Get baseline 404
        baseline = await self.http.get(f"{base}/HexHunterX_fuzz_baseline_404")
        baseline_size = len(baseline.body)

        logger.info(f"Fuzzing hidden endpoints on {base}")

        # Check common paths
        sem = asyncio.Semaphore(25)

        async def _check(path):
            async with sem:
                url = f"{base}{path}"
                resp = await self.http.get(url)
                if (resp.status_code in {200, 201, 204, 301, 302, 401, 403} and
                        not resp.error and
                        abs(len(resp.body) - baseline_size) > 50):
                    return url
                return None

        results = await asyncio.gather(*[_check(p) for p in API_PATHS])
        found.extend([r for r in results if r])

        # Check for backup files of known paths
        for endpoint in found[:10]:
            for ext in BACKUP_EXTENSIONS:
                backup_url = f"{endpoint}{ext}"
                resp = await self.http.get(backup_url)
                if resp.status_code == 200 and not resp.error:
                    found.append(backup_url)

        found = list(set(found))
        logger.success(f"Found {len(found)} hidden endpoints")
        return found
