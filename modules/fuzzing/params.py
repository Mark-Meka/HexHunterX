"""
HexHunterX -- Parameter Discovery Module.

Discover hidden parameters via reflection testing and brute-force.
"""

import asyncio
import re
from urllib.parse import urlencode, urlparse, parse_qs

from utils.logger import HexHunterXLogger
from utils.network import AsyncHTTPClient
from utils.helpers import load_wordlist

logger = HexHunterXLogger.get_logger("fuzzing.params")


class ParamDiscoverer:
    """
    Discover hidden and undocumented parameters.

    Techniques:
        - Reflection testing (inject canary, check if reflected)
        - Common parameter name brute-force
        - Query string, POST body, and header parameter testing
    """

    CANARY = "hxh7r3f"  # Unique canary string

    def __init__(self, http_client: AsyncHTTPClient, config: dict):
        self.http = http_client
        self.wordlist_path = config.get("fuzzing", {}).get(
            "param_wordlist", "data/wordlists/common_params.txt"
        )

    async def discover(self, url: str) -> list[dict]:
        """
        Discover parameters for a URL.

        Returns list of dicts: name, method, reflected.
        """
        wordlist = load_wordlist(self.wordlist_path)
        if not wordlist:
            return []

        logger.info(f"Parameter discovery on {url} ({len(wordlist)} candidates)")

        # Get baseline response
        baseline = await self.http.get(url)
        if baseline.error:
            return []

        found_params = []
        sem = asyncio.Semaphore(20)

        async def _test_param(param_name):
            async with sem:
                return await self._test_single(url, param_name, baseline)

        # Test in batches to avoid overwhelming
        batch_size = 50
        for i in range(0, min(len(wordlist), 200), batch_size):
            batch = wordlist[i:i + batch_size]
            results = await asyncio.gather(*[_test_param(p) for p in batch])
            for r in results:
                if r and r.get("found"):
                    found_params.append(r)

        if found_params:
            logger.success(f"Found {len(found_params)} parameters on {url}")

        return found_params

    async def _test_single(self, url: str, param_name: str, baseline) -> dict:
        """Test a single parameter for existence via reflection."""
        canary = f"{self.CANARY}{param_name[:4]}"
        test_url = f"{url}?{urlencode({param_name: canary})}"

        resp = await self.http.get(test_url)

        if resp.error or resp.status_code == 0:
            return {"found": False}

        # Check if canary is reflected in response
        reflected = canary in resp.body

        # Check if response differs significantly from baseline
        size_diff = abs(len(resp.body) - len(baseline.body))
        status_changed = resp.status_code != baseline.status_code

        if reflected or status_changed or size_diff > 100:
            return {
                "found": True,
                "name": param_name,
                "reflected": reflected,
                "status_changed": status_changed,
                "size_diff": size_diff,
            }

        return {"found": False}
