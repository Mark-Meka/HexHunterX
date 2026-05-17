"""
HexHunterX -- Endpoint Collection Module.

Web crawling, JavaScript parsing, and Wayback Machine URL collection.
"""

import re
from urllib.parse import urljoin, urlparse

from utils.logger import HexHunterXLogger
from utils.network import AsyncHTTPClient
from utils.helpers import deduplicate

logger = HexHunterXLogger.get_logger("recon.endpoints")


class EndpointCollector:
    """
    Collect endpoints from multiple sources.

    Sources:
        - HTML link crawling (BeautifulSoup)
        - JavaScript endpoint extraction (regex)
        - Wayback Machine URL history
    """

    # Regex patterns for JS endpoint extraction
    JS_ENDPOINT_PATTERNS = [
        r'["\'](/[a-zA-Z0-9_/\-\.]+)["\']',
        r'["\']https?://[^"\']+["\']',
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'axios\.\w+\s*\(\s*["\']([^"\']+)["\']',
        r'url\s*[:=]\s*["\']([^"\']+)["\']',
        r'endpoint\s*[:=]\s*["\']([^"\']+)["\']',
        r'href\s*[:=]\s*["\']([^"\']+)["\']',
    ]

    IGNORED_EXTENSIONS = {
        '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2',
        '.ttf', '.eot', '.css', '.map', '.mp4', '.webm', '.mp3',
    }

    def __init__(self, http_client: AsyncHTTPClient, max_depth: int = 2):
        self.http = http_client
        self.max_depth = max_depth

    async def collect(self, base_url: str) -> list[str]:
        """Collect all endpoints for a given URL."""
        logger.info(f"Collecting endpoints from {base_url}")

        all_endpoints = set()

        # HTML crawling
        crawled = await self._crawl(base_url)
        all_endpoints.update(crawled)

        # JS endpoint extraction
        js_endpoints = await self._extract_js_endpoints(base_url)
        all_endpoints.update(js_endpoints)

        # Wayback Machine
        wayback = await self._wayback(urlparse(base_url).hostname or base_url)
        all_endpoints.update(wayback)

        # Smart SPA auth endpoint guessing (for hidden APIs)
        common_auth = [
            "/api/login", "/api/auth", "/rest/user/login", "/api/v1/login",
            "/auth/login", "/users/login", "/api/users/login", "/login.php"
        ]
        for p in common_auth:
            all_endpoints.add(urljoin(base_url, p))

        # Filter and normalize
        filtered = self._filter_endpoints(list(all_endpoints), base_url)

        logger.success(f"Collected {len(filtered)} endpoints from {base_url}")
        return filtered

    async def _crawl(self, url: str, depth: int = 0) -> set[str]:
        """Crawl HTML pages and extract links."""
        if depth >= self.max_depth:
            return set()

        endpoints = set()
        resp = await self.http.get(url)

        if resp.status_code != 200 or resp.error:
            return endpoints

        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.body, "html.parser")

            # Extract links
            for tag in soup.find_all(["a", "link", "script", "form", "iframe"]):
                href = tag.get("href") or tag.get("src") or tag.get("action")
                if href:
                    full_url = urljoin(url, href)
                    endpoints.add(full_url)

            # Extract form action URLs and method info
            for form in soup.find_all("form"):
                action = form.get("action", "")
                if action:
                    endpoints.add(urljoin(url, action))

        except Exception as e:
            logger.debug(f"Crawl error for {url}: {e}")

        return endpoints

    async def _extract_js_endpoints(self, base_url: str) -> set[str]:
        """Extract endpoints from JavaScript files."""
        endpoints = set()
        resp = await self.http.get(base_url)

        if resp.status_code != 200 or resp.error:
            return endpoints

        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.body, "html.parser")

            # Find JS file URLs
            js_urls = []
            for script in soup.find_all("script", src=True):
                js_urls.append(urljoin(base_url, script["src"]))

            # Also parse inline scripts
            for script in soup.find_all("script", src=False):
                if script.string:
                    endpoints.update(self._parse_js_content(script.string, base_url))

            # Fetch and parse external JS files
            for js_url in js_urls[:10]:  # Limit
                js_resp = await self.http.get(js_url)
                if js_resp.status_code == 200 and not js_resp.error:
                    endpoints.update(self._parse_js_content(js_resp.body, base_url))

        except Exception as e:
            logger.debug(f"JS extraction error: {e}")

        return endpoints

    def _parse_js_content(self, js_content: str, base_url: str) -> set[str]:
        """Parse JavaScript content for API endpoints and URLs."""
        endpoints = set()

        for pattern in self.JS_ENDPOINT_PATTERNS:
            matches = re.findall(pattern, js_content)
            for match in matches:
                match = match.strip("'\"")
                if match.startswith("http"):
                    endpoints.add(match)
                elif match.startswith("/"):
                    endpoints.add(urljoin(base_url, match))

        return endpoints

    async def _wayback(self, domain: str) -> set[str]:
        """Fetch historical URLs from Wayback Machine."""
        endpoints = set()
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey&limit=500"

        resp = await self.http.get(url)
        if resp.status_code == 200 and not resp.error:
            for line in resp.body.splitlines():
                line = line.strip()
                if line and line.startswith("http"):
                    endpoints.add(line)

        return endpoints

    def _filter_endpoints(self, endpoints: list[str], base_url: str) -> list[str]:
        """Filter and normalize endpoints."""
        base_domain = urlparse(base_url).hostname

        filtered = []
        for ep in endpoints:
            parsed = urlparse(ep)

            # Skip external domains
            if parsed.hostname and base_domain and base_domain not in parsed.hostname:
                continue

            # Skip static assets
            ext = '.' + parsed.path.rsplit('.', 1)[-1].lower() if '.' in parsed.path else ''
            if ext in self.IGNORED_EXTENSIONS:
                continue

            # Skip fragments-only
            if ep.startswith("#"):
                continue

            filtered.append(ep)

        return deduplicate(sorted(filtered))
