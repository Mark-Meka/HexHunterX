"""
HexHunterX -- ASN / IP Range Mapping Module.

ASN lookup and IP range expansion for target discovery.
"""

import ipaddress
from utils.logger import HexHunterXLogger
from utils.network import AsyncHTTPClient

logger = HexHunterXLogger.get_logger("recon.asn")


class ASNMapper:
    """Map ASN numbers to IP ranges for target expansion."""

    def __init__(self, http_client: AsyncHTTPClient):
        self.http = http_client

    async def lookup_domain(self, domain: str) -> list[dict]:
        """Look up ASN information for a domain."""
        logger.info(f"ASN lookup for {domain}")

        # Use BGPView API
        url = f"https://api.bgpview.io/search?query_term={domain}"
        resp = await self.http.get(url)

        if resp.status_code != 200 or resp.error:
            logger.warning("ASN lookup failed")
            return []

        results = []
        try:
            import json
            data = json.loads(resp.body)
            asns = data.get("data", {}).get("asns", [])
            for asn in asns:
                results.append({
                    "asn": asn.get("asn"),
                    "name": asn.get("name"),
                    "description": asn.get("description"),
                    "country": asn.get("country_code"),
                })
        except Exception as e:
            logger.debug(f"ASN parse error: {e}")

        return results

    async def get_prefixes(self, asn: int) -> list[str]:
        """Get IP prefixes (CIDR ranges) for an ASN."""
        url = f"https://api.bgpview.io/asn/{asn}/prefixes"
        resp = await self.http.get(url)

        if resp.status_code != 200 or resp.error:
            return []

        prefixes = []
        try:
            import json
            data = json.loads(resp.body)
            for prefix in data.get("data", {}).get("ipv4_prefixes", []):
                prefixes.append(prefix.get("prefix", ""))
        except Exception:
            pass

        return [p for p in prefixes if p]

    @staticmethod
    def expand_cidr(cidr: str) -> list[str]:
        """Expand a CIDR range into individual IP addresses."""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            # Limit expansion to /24 or smaller
            if network.prefixlen < 24:
                logger.warning(f"CIDR {cidr} too large, limiting to /24 subnets")
                return [str(subnet) for subnet in network.subnets(new_prefix=24)]
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            return []
