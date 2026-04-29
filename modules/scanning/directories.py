"""
HexHunter -- Directory Brute-Force Module.

Discover hidden directories and files via wordlist-based brute-forcing.
"""

import asyncio
from utils.logger import HexHunterLogger
from utils.network import AsyncHTTPClient
from utils.helpers import load_wordlist, deduplicate

logger = HexHunterLogger.get_logger("scanning.directories")

# Status codes indicating a found directory
VALID_STATUS_CODES = {200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 405}
# Status codes to filter (generic errors)
FILTER_STATUS_CODES = {404, 503}


class DirectoryBruter:
    """
    Directory brute-force scanner.

    Features:
        - Wordlist-based directory/file discovery
        - Smart filtering by status code and response size
        - Deduplication of similar responses
    """

    def __init__(self, http_client: AsyncHTTPClient, config: dict):
        self.http = http_client
        self.wordlist_path = config.get("scanning", {}).get(
            "dir_wordlist", "data/wordlists/common_dirs.txt"
        )
        self.extensions = config.get("scanning", {}).get(
            "extensions", ["", ".php", ".html", ".js", ".json", ".txt"]
        )

    async def brute(self, base_url: str) -> list[dict]:
        """
        Brute-force directories on a target URL.

        Returns list of dicts: url, status_code, content_length.
        """
        wordlist = load_wordlist(self.wordlist_path)
        if not wordlist:
            logger.warning("No directory wordlist found")
            return []

        # Build URL list with extensions
        urls = []
        base = base_url.rstrip("/")
        for word in wordlist[:300]:  # Limit for performance
            for ext in self.extensions:
                urls.append(f"{base}/{word}{ext}")

        logger.info(f"Brute-forcing {len(urls)} paths on {base_url}")

        # Get baseline 404 response for smart filtering
        baseline = await self._get_baseline(base_url)

        results = []
        sem = asyncio.Semaphore(30)

        async def _check(url):
            async with sem:
                return await self._check_path(url, baseline)

        gathered = await asyncio.gather(*[_check(u) for u in urls], return_exceptions=True)

        for r in gathered:
            if isinstance(r, dict) and r.get("found"):
                results.append(r)

        # Deduplicate by content length (catch custom 404s)
        results = self._smart_filter(results)

        logger.success(f"Found {len(results)} directories/files")
        return results

    async def _get_baseline(self, base_url: str) -> dict:
        """Get baseline 404 response for comparison."""
        fake_path = f"{base_url}/hexhunter_nonexistent_path_test_12345"
        resp = await self.http.get(fake_path)
        return {
            "status_code": resp.status_code,
            "content_length": len(resp.body),
        }

    async def _check_path(self, url: str, baseline: dict) -> dict:
        """Check a single path."""
        resp = await self.http.get(url)

        if resp.error or resp.status_code in FILTER_STATUS_CODES:
            return {"found": False}

        if resp.status_code not in VALID_STATUS_CODES:
            return {"found": False}

        # Smart filter: skip if response matches baseline 404
        body_len = len(resp.body)
        if (resp.status_code == baseline["status_code"] and
                abs(body_len - baseline["content_length"]) < 50):
            return {"found": False}

        return {
            "found": True,
            "url": url,
            "status_code": resp.status_code,
            "content_length": body_len,
        }

    @staticmethod
    def _smart_filter(results: list[dict]) -> list[dict]:
        """Filter out false positives (many identical response sizes)."""
        if len(results) < 5:
            return results

        # Count response sizes
        size_counts: dict[int, int] = {}
        for r in results:
            size = r.get("content_length", 0)
            size_counts[size] = size_counts.get(size, 0) + 1

        # If more than 50% share the same size, it's likely a custom 404
        total = len(results)
        filtered = []
        for r in results:
            size = r.get("content_length", 0)
            if size_counts.get(size, 0) > total * 0.5:
                continue  # Likely false positive
            filtered.append(r)

        return filtered
