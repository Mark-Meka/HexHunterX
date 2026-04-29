"""
HexHunter -- Subdomain Enumeration Module.

Passive (crt.sh, APIs), active (DNS brute-force), and permutation-based enumeration.
"""

import asyncio
import json
from pathlib import Path

from utils.logger import HexHunterLogger
from utils.network import AsyncHTTPClient
from utils.helpers import deduplicate, load_wordlist

logger = HexHunterLogger.get_logger("recon.subdomains")


class SubdomainEnumerator:
    """
    Multi-source subdomain enumeration engine.

    Sources:
        - Passive: crt.sh (Certificate Transparency), HackerTarget
        - Active: DNS brute-force with wordlist
        - Permutation: prefix/suffix generation
    """

    def __init__(self, http_client: AsyncHTTPClient, config: dict):
        self.http = http_client
        self.config = config
        self.wordlist_path = config.get("recon", {}).get(
            "subdomain_wordlist", "data/wordlists/common_subdomains.txt"
        )

    async def enumerate(self, domain: str) -> list[str]:
        """Run all enumeration techniques and return deduplicated subdomains."""
        logger.info(f"Enumerating subdomains for [target]{domain}[/target]")
        all_subs = set()

        # Passive enumeration
        passive_sources = [
            ("crt.sh", self._crtsh),
            ("HackerTarget", self._hackertarget),
        ]

        for name, func in passive_sources:
            try:
                subs = await func(domain)
                logger.info(f"  {name}: {len(subs)} subdomains")
                all_subs.update(subs)
            except Exception as e:
                logger.warning(f"  {name} failed: {e}")

        # Active brute-force
        try:
            brute_subs = await self._bruteforce(domain)
            logger.info(f"  Brute-force: {len(brute_subs)} subdomains")
            all_subs.update(brute_subs)
        except Exception as e:
            logger.warning(f"  Brute-force failed: {e}")

        # Permutation
        perm_subs = self._permutations(domain, list(all_subs))
        all_subs.update(perm_subs)

        # Filter and deduplicate
        result = sorted(set(
            s.lower().strip().rstrip(".")
            for s in all_subs
            if s.endswith(f".{domain}") or s == domain
        ))

        logger.success(f"Total unique subdomains: {len(result)}")
        return result

    async def _crtsh(self, domain: str) -> list[str]:
        """Query crt.sh Certificate Transparency logs."""
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = await self.http.get(url)

        if resp.status_code != 200 or resp.error:
            return []

        subdomains = set()
        try:
            entries = json.loads(resp.body)
            for entry in entries:
                name = entry.get("name_value", "")
                for line in name.splitlines():
                    line = line.strip().lower()
                    if line and "*" not in line:
                        subdomains.add(line)
        except (json.JSONDecodeError, KeyError):
            pass

        return list(subdomains)

    async def _hackertarget(self, domain: str) -> list[str]:
        """Query HackerTarget API for subdomains."""
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        resp = await self.http.get(url)

        if resp.status_code != 200 or resp.error:
            return []

        subdomains = []
        for line in resp.body.splitlines():
            line = line.strip()
            if "," in line:
                sub = line.split(",")[0].strip().lower()
                if sub:
                    subdomains.append(sub)

        return subdomains

    async def _bruteforce(self, domain: str) -> list[str]:
        """DNS brute-force using wordlist."""
        import dns.resolver

        wordlist = load_wordlist(self.wordlist_path)
        if not wordlist:
            logger.warning("No subdomain wordlist found, skipping brute-force")
            return []

        found = []
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3

        # Limit wordlist size for performance
        wordlist = wordlist[:500]

        async def _resolve(word):
            subdomain = f"{word}.{domain}"
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, resolver.resolve, subdomain, "A")
                return subdomain
            except Exception:
                return None

        sem = asyncio.Semaphore(50)

        async def _limited_resolve(word):
            async with sem:
                return await _resolve(word)

        results = await asyncio.gather(*[_limited_resolve(w) for w in wordlist])
        found = [r for r in results if r]

        return found

    def _permutations(self, domain: str, existing: list[str]) -> list[str]:
        """Generate subdomain permutations from existing subdomains."""
        prefixes = ["dev", "staging", "test", "api", "admin", "beta", "internal",
                     "stage", "uat", "pre", "demo", "sandbox"]
        permutations = set()

        for sub in existing[:50]:  # Limit to avoid explosion
            parts = sub.replace(f".{domain}", "").split(".")
            if parts and parts[0]:
                base = parts[0]
                for prefix in prefixes:
                    permutations.add(f"{prefix}-{base}.{domain}")
                    permutations.add(f"{base}-{prefix}.{domain}")

        return list(permutations)
