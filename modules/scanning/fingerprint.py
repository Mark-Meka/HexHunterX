"""
HexHunter -- Technology Fingerprinting Module.

Detect web technologies, frameworks, and CMS from HTTP responses.
"""

import re
from utils.logger import HexHunterLogger
from utils.network import AsyncHTTPClient

logger = HexHunterLogger.get_logger("scanning.fingerprint")

# Technology detection rules: (header/body pattern, technology name)
HEADER_RULES = [
    ("Server", r"nginx/?(\S*)", "Nginx"),
    ("Server", r"Apache/?(\S*)", "Apache"),
    ("Server", r"Microsoft-IIS/?(\S*)", "IIS"),
    ("Server", r"cloudflare", "Cloudflare"),
    ("Server", r"LiteSpeed", "LiteSpeed"),
    ("X-Powered-By", r"PHP/?(\S*)", "PHP"),
    ("X-Powered-By", r"ASP\.NET", "ASP.NET"),
    ("X-Powered-By", r"Express", "Express.js"),
    ("X-Powered-By", r"Next\.js", "Next.js"),
    ("X-Generator", r"WordPress (\S+)", "WordPress"),
    ("X-Generator", r"Drupal", "Drupal"),
    ("X-Drupal-Cache", r".*", "Drupal"),
    ("X-Shopify-Stage", r".*", "Shopify"),
    ("X-Wix-Request-Id", r".*", "Wix"),
]

BODY_RULES = [
    (r'wp-content/', "WordPress"),
    (r'wp-includes/', "WordPress"),
    (r'/sites/default/files/', "Drupal"),
    (r'Joomla!', "Joomla"),
    (r'<!-- Powered by Magento', "Magento"),
    (r'<meta name="generator" content="Hugo', "Hugo"),
    (r'<meta name="generator" content="Jekyll', "Jekyll"),
    (r'__next', "Next.js"),
    (r'__nuxt', "Nuxt.js"),
    (r'ng-version', "Angular"),
    (r'data-reactroot', "React"),
    (r'__vue', "Vue.js"),
    (r'cdn\.shopify\.com', "Shopify"),
    (r'jquery', "jQuery"),
    (r'bootstrap', "Bootstrap"),
]


class TechFingerprinter:
    """
    Detect web technologies from HTTP response headers and body.

    Checks for: web servers, languages, frameworks, CMS platforms.
    """

    def __init__(self, http_client: AsyncHTTPClient):
        self.http = http_client

    async def fingerprint(self, url: str) -> list[str]:
        """
        Fingerprint technologies for a given URL.

        Returns list of detected technology names.
        """
        technologies = set()

        resp = await self.http.get(url)
        if resp.error:
            return []

        # Check headers
        for header_name, pattern, tech in HEADER_RULES:
            header_val = resp.headers.get(header_name, "")
            if header_val and re.search(pattern, header_val, re.IGNORECASE):
                technologies.add(tech)

        # Check body
        for pattern, tech in BODY_RULES:
            if re.search(pattern, resp.body, re.IGNORECASE):
                technologies.add(tech)

        # Check cookies
        cookies = resp.headers.get("Set-Cookie", "")
        if "PHPSESSID" in cookies:
            technologies.add("PHP")
        if "JSESSIONID" in cookies:
            technologies.add("Java")
        if "ASP.NET" in cookies:
            technologies.add("ASP.NET")
        if "laravel_session" in cookies:
            technologies.add("Laravel")
        if "csrftoken" in cookies and "django" in resp.body.lower():
            technologies.add("Django")

        if technologies:
            logger.info(f"  Technologies on {url}: {', '.join(sorted(technologies))}")

        return sorted(technologies)
