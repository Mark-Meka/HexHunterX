"""
HexHunter -- Async HTTP Client with Retry & Rate Limiting.
"""

import asyncio
import time
from dataclasses import dataclass, field

import aiohttp

from utils.logger import HexHunterLogger

logger = HexHunterLogger.get_logger("network")


@dataclass
class HTTPResponse:
    """Structured HTTP response for evidence storage."""
    url: str
    method: str
    status_code: int
    headers: dict[str, str]
    body: str
    elapsed_ms: float
    redirect_chain: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "url": self.url, "method": self.method, "status_code": self.status_code,
            "headers": self.headers, "body": self.body[:5000],
            "elapsed_ms": self.elapsed_ms, "redirect_chain": self.redirect_chain,
            "error": self.error,
        }


@dataclass
class HTTPRequest:
    """Structured HTTP request for evidence storage."""
    url: str
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    params: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"url": self.url, "method": self.method, "headers": self.headers,
                "body": self.body, "params": self.params}


class RateLimiter:
    """Token bucket rate limiter."""
    def __init__(self, rps: float = 10.0):
        self.rate = rps
        self.tokens = rps
        self.max_tokens = rps
        self.last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            self.tokens = min(self.max_tokens, self.tokens + (now - self.last_refill) * self.rate)
            self.last_refill = now
            if self.tokens < 1:
                await asyncio.sleep((1 - self.tokens) / self.rate)
                self.tokens = 0
            else:
                self.tokens -= 1


class AsyncHTTPClient:
    """Async HTTP client with retry, rate limiting, and evidence capture."""

    def __init__(self, rate_limit=10.0, max_retries=3, timeout=10,
                 user_agent="HexHunter/1.0", max_connections=100,
                 follow_redirects=True, verify_ssl=False):
        self.rate_limiter = RateLimiter(rate_limit)
        self.max_retries = max_retries
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.user_agent = user_agent
        self.max_connections = max_connections
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        self._session: aiohttp.ClientSession | None = None
        self._request_count = 0
        self._error_count = 0

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, *args):
        await self.close()

    async def start(self):
        connector = aiohttp.TCPConnector(limit=self.max_connections, ssl=self.verify_ssl)
        self._session = aiohttp.ClientSession(
            connector=connector, timeout=self.timeout,
            headers={"User-Agent": self.user_agent})

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
            await asyncio.sleep(0.25)

    async def request(self, method, url, headers=None, data=None, params=None,
                      follow_redirects=None) -> HTTPResponse:
        if not self._session:
            await self.start()
        await self.rate_limiter.acquire()
        allow = follow_redirects if follow_redirects is not None else self.follow_redirects
        last_error = None

        for attempt in range(self.max_retries):
            try:
                start = time.monotonic()
                async with self._session.request(
                    method=method.upper(), url=url, headers=headers,
                    data=data, params=params, allow_redirects=allow,
                ) as resp:
                    elapsed = (time.monotonic() - start) * 1000
                    try:
                        body = await resp.text(errors="replace")
                    except Exception:
                        body = ""
                    chain = [str(r.url) for r in resp.history] if resp.history else []
                    self._request_count += 1
                    return HTTPResponse(
                        url=str(resp.url), method=method.upper(),
                        status_code=resp.status, headers=dict(resp.headers),
                        body=body, elapsed_ms=round(elapsed, 2),
                        redirect_chain=chain)
            except asyncio.TimeoutError:
                last_error = "Timeout"
            except aiohttp.ClientError as e:
                last_error = str(e)
            except Exception as e:
                last_error = str(e)
            if attempt < self.max_retries - 1:
                await asyncio.sleep(2 ** attempt)

        self._error_count += 1
        return HTTPResponse(url=url, method=method.upper(), status_code=0,
                            headers={}, body="", elapsed_ms=0, error=last_error)

    async def get(self, url, **kw) -> HTTPResponse:
        return await self.request("GET", url, **kw)

    async def post(self, url, **kw) -> HTTPResponse:
        return await self.request("POST", url, **kw)

    async def head(self, url, **kw) -> HTTPResponse:
        return await self.request("HEAD", url, **kw)

    @property
    def stats(self) -> dict:
        return {"total_requests": self._request_count, "total_errors": self._error_count}
