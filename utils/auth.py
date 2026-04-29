"""
HexHunterX -- Authentication Manager.

Handles cookie, JWT/Bearer, custom header, and auto-login authentication
for authenticated scanning behind login walls.
"""

import re
from urllib.parse import urlencode

from utils.logger import HexHunterXLogger

logger = HexHunterXLogger.get_logger("auth")


class AuthManager:
    """
    Manage authentication state for scanning sessions.

    Supports:
        - Raw cookie injection (--cookie)
        - Bearer / JWT token injection (--auth-token)
        - Custom header injection (--auth-header)
        - Auto-login via form POST (--login-url + credentials)
    """

    def __init__(self):
        self.auth_headers: dict[str, str] = {}
        self.auth_cookies: dict[str, str] = {}
        self._login_url: str | None = None
        self._username: str | None = None
        self._password: str | None = None
        self._is_authenticated: bool = False

    @classmethod
    def from_config(cls, cli_args: dict) -> "AuthManager":
        """Create an AuthManager from parsed CLI arguments."""
        mgr = cls()

        # Cookie auth: --cookie "session=abc; token=xyz"
        cookie_str = cli_args.get("cookie")
        if cookie_str:
            mgr.auth_cookies = cls._parse_cookie_string(cookie_str)
            mgr._is_authenticated = True
            logger.info(f"Auth: {len(mgr.auth_cookies)} cookies loaded")

        # Bearer/JWT: --auth-token "eyJhbG..."
        token = cli_args.get("auth_token")
        if token:
            # Strip "Bearer " prefix if user included it
            token = token.removeprefix("Bearer ").strip()
            mgr.auth_headers["Authorization"] = f"Bearer {token}"
            mgr._is_authenticated = True
            logger.info("Auth: Bearer token loaded")

        # Custom header: --auth-header "X-API-Key: sk_live_abc"
        header_str = cli_args.get("auth_header")
        if header_str and ":" in header_str:
            name, _, value = header_str.partition(":")
            mgr.auth_headers[name.strip()] = value.strip()
            mgr._is_authenticated = True
            logger.info(f"Auth: Custom header '{name.strip()}' loaded")

        # Auto-login credentials (will be used in login() call)
        mgr._login_url = cli_args.get("login_url")
        mgr._username = cli_args.get("login_user")
        mgr._password = cli_args.get("login_pass")

        return mgr

    @property
    def is_authenticated(self) -> bool:
        return self._is_authenticated

    @property
    def needs_login(self) -> bool:
        return bool(self._login_url and self._username and self._password)

    async def login(self, http_client) -> bool:
        """
        Auto-login via form POST.

        Steps:
            1. GET the login page
            2. Extract CSRF token from the form (if present)
            3. POST credentials + CSRF token
            4. Capture cookies from Set-Cookie headers
            5. Verify login succeeded (check for redirect or success indicators)
        """
        if not self.needs_login:
            return False

        logger.info(f"Auto-login: {self._login_url}")

        # Step 1: GET login page to extract CSRF token
        login_page = await http_client.get(self._login_url)
        if login_page.error:
            logger.error(f"Auto-login: failed to load login page: {login_page.error}")
            return False

        # Step 2: Extract CSRF token
        csrf_token, csrf_field = self._extract_csrf(login_page.body)
        if csrf_token:
            logger.info(f"Auto-login: CSRF token extracted ({csrf_field})")

        # Extract form action URL
        form_action = self._extract_form_action(login_page.body) or self._login_url

        # Detect field names from the form
        username_field, password_field = self._detect_login_fields(login_page.body)

        # Step 3: POST credentials
        post_data = {
            username_field: self._username,
            password_field: self._password,
        }
        if csrf_token and csrf_field:
            post_data[csrf_field] = csrf_token

        login_resp = await http_client.post(
            form_action,
            data=urlencode(post_data),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            follow_redirects=False,
        )

        # Step 4: Capture cookies from response
        cookies_captured = self._capture_cookies(login_resp.headers)

        # Step 5: Verify login
        if login_resp.status_code in (301, 302, 303, 307, 308):
            # Redirect after login = usually success
            self._is_authenticated = True
            logger.success(
                f"Auto-login: success (redirect {login_resp.status_code}, "
                f"{len(cookies_captured)} cookies captured)"
            )
            return True
        elif login_resp.status_code == 200:
            # Check if response has success indicators
            body_lower = login_resp.body.lower()
            fail_indicators = ["invalid", "incorrect", "failed", "error", "wrong password"]
            success_indicators = ["dashboard", "welcome", "logout", "profile", "account"]

            has_fail = any(kw in body_lower for kw in fail_indicators)
            has_success = any(kw in body_lower for kw in success_indicators)

            if has_success and not has_fail:
                self._is_authenticated = True
                logger.success("Auto-login: success (success indicators detected)")
                return True
            elif cookies_captured:
                self._is_authenticated = True
                logger.success(f"Auto-login: likely success ({len(cookies_captured)} cookies)")
                return True
            else:
                logger.warning("Auto-login: login may have failed (no success indicators)")
                return False

        logger.warning(f"Auto-login: unexpected status {login_resp.status_code}")
        return False

    async def check_session(self, http_client, test_url: str) -> bool:
        """Check if the current session is still valid."""
        if not self._is_authenticated:
            return False

        resp = await http_client.get(test_url)
        if resp.error:
            return False

        # If we get a login page back, session expired
        if resp.status_code in (401, 403):
            return False

        body_lower = resp.body.lower()
        login_indicators = [
            "login", "sign in", "log in", 'name="password"',
            "authentication required", "unauthorized",
        ]
        if any(kw in body_lower for kw in login_indicators):
            # Might be a login page redirect
            if "logout" not in body_lower and "dashboard" not in body_lower:
                return False

        return True

    async def refresh_if_needed(self, http_client, test_url: str) -> bool:
        """Re-authenticate if session expired."""
        if await self.check_session(http_client, test_url):
            return True

        logger.warning("Session expired, attempting re-login...")
        if self.needs_login:
            return await self.login(http_client)

        logger.error("Session expired and no login credentials available")
        return False

    # ─── Private Helpers ──────────────────────────────

    @staticmethod
    def _parse_cookie_string(cookie_str: str) -> dict[str, str]:
        """Parse 'name=value; name2=value2' into a dict."""
        cookies = {}
        for part in cookie_str.split(";"):
            part = part.strip()
            if "=" in part:
                name, _, value = part.partition("=")
                cookies[name.strip()] = value.strip()
        return cookies

    def _extract_csrf(self, html: str) -> tuple[str | None, str | None]:
        """Extract CSRF token value and field name from HTML form."""
        csrf_names = [
            "csrf_token", "csrfmiddlewaretoken", "_csrf", "_token",
            "authenticity_token", "anti-csrf-token", "__RequestVerificationToken",
            "csrf", "xsrf_token", "_xsrf", "nonce", "token",
        ]

        for name in csrf_names:
            # Hidden input: <input type="hidden" name="csrf_token" value="abc123">
            pattern = rf'<input[^>]*name=["\']({re.escape(name)})["\'][^>]*value=["\']([^"\']*)["\']'
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(2), match.group(1)

            # Reverse attribute order: value before name
            pattern2 = rf'<input[^>]*value=["\']([^"\']*)["\'][^>]*name=["\']({re.escape(name)})["\']'
            match2 = re.search(pattern2, html, re.IGNORECASE)
            if match2:
                return match2.group(1), match2.group(2)

        # Meta tag: <meta name="csrf-token" content="abc123">
        meta_pattern = r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']*)["\']'
        meta_match = re.search(meta_pattern, html, re.IGNORECASE)
        if meta_match:
            return meta_match.group(1), "csrf-token"

        return None, None

    @staticmethod
    def _extract_form_action(html: str) -> str | None:
        """Extract the action URL from a login form."""
        # Look for a form containing a password field
        form_pattern = re.compile(
            r'<form\s[^>]*?action=["\']([^"\']*)["\'][^>]*?>(.*?)</form>',
            re.DOTALL | re.IGNORECASE,
        )
        for match in form_pattern.finditer(html):
            form_body = match.group(2)
            if 'type="password"' in form_body or "type='password'" in form_body:
                return match.group(1)
        return None

    @staticmethod
    def _detect_login_fields(html: str) -> tuple[str, str]:
        """Detect username and password field names from the form."""
        username_field = "username"
        password_field = "password"

        # Find password field
        pass_match = re.search(
            r'<input[^>]*type=["\']password["\'][^>]*name=["\']([^"\']*)["\']',
            html, re.IGNORECASE,
        )
        if pass_match:
            password_field = pass_match.group(1)

        # Find username/email field (text or email input near the password field)
        user_patterns = [
            r'<input[^>]*name=["\']([^"\']*(?:user|login|email|name|account)[^"\']*)["\']',
            r'<input[^>]*type=["\'](?:text|email)["\'][^>]*name=["\']([^"\']*)["\']',
        ]
        for pattern in user_patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                username_field = match.group(1)
                break

        return username_field, password_field

    def _capture_cookies(self, headers: dict) -> dict[str, str]:
        """Extract cookies from Set-Cookie headers."""
        captured = {}
        for key, value in headers.items():
            if key.lower() == "set-cookie":
                parts = value.split(";")[0]  # Get name=value part
                if "=" in parts:
                    name, _, val = parts.partition("=")
                    captured[name.strip()] = val.strip()
                    self.auth_cookies[name.strip()] = val.strip()
        return captured
