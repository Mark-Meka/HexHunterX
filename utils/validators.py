"""
HexHunter -- Input Validation & Normalization.

Validates domains, IPs, CIDRs, URLs, and manages scope filtering.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse

import tldextract


class TargetType(Enum):
    """Classification of target input types."""
    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"
    URL = "url"
    UNKNOWN = "unknown"


@dataclass
class ValidatedTarget:
    """Represents a validated and normalized target."""
    raw_input: str
    target_type: TargetType
    normalized: str
    domain: str | None = None
    ip: str | None = None
    cidr: str | None = None
    port: int | None = None
    scheme: str = "https"
    is_valid: bool = True
    errors: list[str] = field(default_factory=list)


class ScopeManager:
    """
    Manages in-scope and out-of-scope targets.

    Supports wildcard domains (*.example.com) and CIDR ranges.
    """

    def __init__(self):
        self.in_scope: list[str] = []
        self.out_of_scope: list[str] = []
        self._in_scope_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._out_scope_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []

    def add_in_scope(self, target: str):
        """Add a target pattern to the in-scope list."""
        self.in_scope.append(target.lower().strip())
        try:
            net = ipaddress.ip_network(target, strict=False)
            self._in_scope_networks.append(net)
        except ValueError:
            pass

    def add_out_of_scope(self, target: str):
        """Add a target pattern to the out-of-scope list."""
        self.out_of_scope.append(target.lower().strip())
        try:
            net = ipaddress.ip_network(target, strict=False)
            self._out_scope_networks.append(net)
        except ValueError:
            pass

    def is_in_scope(self, target: str) -> bool:
        """
        Check if a target is within scope.

        Rules:
            1. If out-of-scope list matches → False
            2. If in-scope list is empty → True (everything in scope)
            3. If in-scope list matches → True
            4. Otherwise → False
        """
        target_lower = target.lower().strip()

        # Check out-of-scope first (deny takes precedence)
        for pattern in self.out_of_scope:
            if self._matches_pattern(target_lower, pattern):
                return False

        # Check IP-based out-of-scope
        try:
            target_ip = ipaddress.ip_address(target_lower)
            for net in self._out_scope_networks:
                if target_ip in net:
                    return False
        except ValueError:
            pass

        # If no in-scope defined, everything is in scope
        if not self.in_scope:
            return True

        # Check in-scope patterns
        for pattern in self.in_scope:
            if self._matches_pattern(target_lower, pattern):
                return True

        # Check IP-based in-scope
        try:
            target_ip = ipaddress.ip_address(target_lower)
            for net in self._in_scope_networks:
                if target_ip in net:
                    return True
        except ValueError:
            pass

        return False

    @staticmethod
    def _matches_pattern(target: str, pattern: str) -> bool:
        """Match a target against a scope pattern (supports wildcards)."""
        if pattern.startswith("*."):
            # Wildcard domain: *.example.com matches sub.example.com
            suffix = pattern[1:]  # .example.com
            return target.endswith(suffix) or target == pattern[2:]
        return target == pattern


class InputValidator:
    """
    Validates and normalizes target inputs.

    Supports domains, IPs, CIDRs, and URLs with thorough validation.
    """

    # Regex patterns
    DOMAIN_REGEX = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
    )
    IP_V4_REGEX = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$"
    )
    CIDR_V4_REGEX = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$"
    )

    @classmethod
    def validate(cls, raw_input: str) -> ValidatedTarget:
        """
        Validate and classify a raw target input.

        Returns a ValidatedTarget with type classification and normalized form.
        """
        raw = raw_input.strip()

        if not raw:
            return ValidatedTarget(
                raw_input=raw_input,
                target_type=TargetType.UNKNOWN,
                normalized="",
                is_valid=False,
                errors=["Empty target input"],
            )

        # Try URL first
        if raw.startswith(("http://", "https://")):
            return cls._validate_url(raw)

        # Try CIDR
        if "/" in raw and cls.CIDR_V4_REGEX.match(raw):
            return cls._validate_cidr(raw)

        # Try IP
        if cls.IP_V4_REGEX.match(raw):
            return cls._validate_ip(raw)

        # Try domain
        return cls._validate_domain(raw)

    @classmethod
    def _validate_domain(cls, raw: str) -> ValidatedTarget:
        """Validate a domain name."""
        # Strip protocol if accidentally included without //
        domain = raw.lower().strip(".")

        # Use tldextract for robust parsing
        extracted = tldextract.extract(domain)

        if not extracted.domain or not extracted.suffix:
            return ValidatedTarget(
                raw_input=raw,
                target_type=TargetType.UNKNOWN,
                normalized=domain,
                is_valid=False,
                errors=[f"Invalid domain: {raw}"],
            )

        # Reconstruct FQDN
        fqdn = extracted.fqdn.rstrip(".")

        if not cls.DOMAIN_REGEX.match(fqdn):
            return ValidatedTarget(
                raw_input=raw,
                target_type=TargetType.DOMAIN,
                normalized=fqdn,
                domain=fqdn,
                is_valid=False,
                errors=[f"Domain contains invalid characters: {fqdn}"],
            )

        return ValidatedTarget(
            raw_input=raw,
            target_type=TargetType.DOMAIN,
            normalized=fqdn,
            domain=fqdn,
        )

    @classmethod
    def _validate_ip(cls, raw: str) -> ValidatedTarget:
        """Validate an IPv4/IPv6 address."""
        try:
            ip_obj = ipaddress.ip_address(raw)
            return ValidatedTarget(
                raw_input=raw,
                target_type=TargetType.IP,
                normalized=str(ip_obj),
                ip=str(ip_obj),
            )
        except ValueError:
            return ValidatedTarget(
                raw_input=raw,
                target_type=TargetType.UNKNOWN,
                normalized=raw,
                is_valid=False,
                errors=[f"Invalid IP address: {raw}"],
            )

    @classmethod
    def _validate_cidr(cls, raw: str) -> ValidatedTarget:
        """Validate a CIDR range."""
        try:
            network = ipaddress.ip_network(raw, strict=False)
            return ValidatedTarget(
                raw_input=raw,
                target_type=TargetType.CIDR,
                normalized=str(network),
                cidr=str(network),
                ip=str(network.network_address),
            )
        except ValueError:
            return ValidatedTarget(
                raw_input=raw,
                target_type=TargetType.UNKNOWN,
                normalized=raw,
                is_valid=False,
                errors=[f"Invalid CIDR range: {raw}"],
            )

    @classmethod
    def _validate_url(cls, raw: str) -> ValidatedTarget:
        """Validate a URL and extract components."""
        try:
            parsed = urlparse(raw)
            if not parsed.hostname:
                raise ValueError("No hostname found")

            hostname = parsed.hostname.lower()
            port = parsed.port

            # Determine if hostname is IP or domain
            try:
                ip_obj = ipaddress.ip_address(hostname)
                return ValidatedTarget(
                    raw_input=raw,
                    target_type=TargetType.URL,
                    normalized=raw.rstrip("/"),
                    ip=str(ip_obj),
                    port=port,
                    scheme=parsed.scheme,
                )
            except ValueError:
                pass

            return ValidatedTarget(
                raw_input=raw,
                target_type=TargetType.URL,
                normalized=raw.rstrip("/"),
                domain=hostname,
                port=port,
                scheme=parsed.scheme,
            )

        except Exception as e:
            return ValidatedTarget(
                raw_input=raw,
                target_type=TargetType.UNKNOWN,
                normalized=raw,
                is_valid=False,
                errors=[f"Invalid URL: {e}"],
            )

    @staticmethod
    def normalize_url(url: str, default_scheme: str = "https") -> str:
        """Normalize a URL by adding scheme if missing, lowering, stripping trailing slashes."""
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = f"{default_scheme}://{url}"
        parsed = urlparse(url)
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")
        if parsed.query:
            normalized += f"?{parsed.query}"
        return normalized
