"""
Centralized configuration and URL validation for Ghost Scanner.

Provides the ScanConfig dataclass with strict URL validation to prevent
SSRF-like behavior on the scanner itself, and a clean SSL verification toggle.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Allowed URL schemes — reject file://, ftp://, data://, etc.
# ---------------------------------------------------------------------------
_ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})

# Private / reserved IP ranges that must be rejected by default
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


class InvalidTargetError(Exception):
    """Raised when the target URL fails validation."""


def validate_url(url: str, *, allow_private: bool = False) -> str:
    """Validate and normalise a target URL.

    Args:
        url: Raw URL string from user input.
        allow_private: If True, permits scanning of private/internal IPs.
                       Useful for authorised internal infrastructure tests.

    Returns:
        The normalised URL with a valid scheme.

    Raises:
        InvalidTargetError: If the URL is malformed, uses a forbidden scheme,
            or resolves to a private IP when ``allow_private`` is False.
    """
    url = url.strip()
    if not url:
        raise InvalidTargetError("Target URL cannot be empty.")

    # Auto-prefix scheme if missing
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    parsed = urlparse(url)

    # --- Scheme check ---
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise InvalidTargetError(
            f"Scheme '{parsed.scheme}://' is not allowed. "
            f"Use one of: {', '.join(_ALLOWED_SCHEMES)}"
        )

    # --- Netloc check ---
    if not parsed.netloc:
        raise InvalidTargetError(
            f"Invalid URL '{url}': missing hostname / network location."
        )

    # --- Private IP check ---
    if not allow_private:
        try:
            resolved_ip = socket.gethostbyname(parsed.hostname or "")
            ip_obj = ipaddress.ip_address(resolved_ip)
            for network in _PRIVATE_NETWORKS:
                if ip_obj in network:
                    raise InvalidTargetError(
                        f"Target '{parsed.hostname}' resolves to private IP "
                        f"{resolved_ip}. Use --allow-private to permit this."
                    )
        except socket.gaierror:
            raise InvalidTargetError(
                f"Cannot resolve hostname '{parsed.hostname}'."
            )

    return url


def resolve_target_ip(hostname: str) -> str:
    """Resolve a hostname to its IPv4 address.

    Returns:
        The resolved IP string, or ``'Unresolvable'`` on failure.
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return "Unresolvable"


@dataclass
class ScanConfig:
    """Immutable scan session configuration.

    Attributes:
        target_url:      Validated target URL (with scheme).
        domain:          Extracted netloc / hostname.
        target_ip:       Resolved IPv4 of the target.
        timeout:         Per-request timeout in seconds.
        ssl_verify:      Whether to verify TLS certificates.
        allow_private:   Permit scanning of RFC-1918 private IPs.
        max_concurrency: Maximum concurrent async requests.
        output_path:     File path for the JSON report output.
    """

    target_url: str
    domain: str = ""
    target_ip: str = "Detecting..."
    timeout: float = 10.0
    ssl_verify: bool = True
    allow_private: bool = False
    max_concurrency: int = 50
    output_path: str = ""
    modules: list[str] = field(default_factory=lambda: ["recon", "headers", "cookies"])

    def __post_init__(self) -> None:
        """Validate and resolve target upon creation."""
        self.target_url = validate_url(
            self.target_url, allow_private=self.allow_private
        )
        parsed = urlparse(self.target_url)
        self.domain = parsed.netloc
        self.target_ip = resolve_target_ip(parsed.hostname or "")
