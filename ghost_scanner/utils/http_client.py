"""
Async HTTP client wrapper built on httpx with HTTP/2 support.

Centralises connection pooling, timeout management, user-agent rotation,
and structured error handling for all scanner modules.
"""

from __future__ import annotations

import logging
import random
from types import TracebackType
from typing import Any

import httpx

logger = logging.getLogger("ghost_scanner.http")

# Pool of realistic User-Agent strings for header rotation
_USER_AGENTS: list[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
]


class HttpClient:
    """Async HTTP client with HTTP/2, connection pooling, and retry logic.

    Usage::

        async with HttpClient(timeout=10.0, ssl_verify=True) as client:
            response = await client.fetch("https://example.com")
    """

    def __init__(
        self,
        *,
        timeout: float = 10.0,
        ssl_verify: bool = True,
        max_connections: int = 50,
    ) -> None:
        self._timeout = httpx.Timeout(
            timeout, connect=timeout, read=timeout, write=timeout, pool=timeout
        )
        self._limits = httpx.Limits(
            max_connections=max_connections,
            max_keepalive_connections=max_connections // 2,
        )
        self._ssl_verify = ssl_verify
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "HttpClient":
        self._client = httpx.AsyncClient(
            http2=True,
            timeout=self._timeout,
            limits=self._limits,
            verify=self._ssl_verify,
            follow_redirects=True,
        )
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if self._client:
            await self._client.aclose()

    @property
    def client(self) -> httpx.AsyncClient:
        """Return the underlying httpx client; raises if not initialised."""
        if self._client is None:
            raise RuntimeError(
                "HttpClient is not initialised. Use 'async with HttpClient() as c:'."
            )
        return self._client

    def _random_headers(self) -> dict[str, str]:
        """Generate request headers with a rotated User-Agent."""
        return {
            "User-Agent": random.choice(_USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }

    async def fetch(
        self,
        url: str,
        *,
        method: str = "GET",
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json_data: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> httpx.Response | None:
        """Send an HTTP request with structured error handling.

        Args:
            url:       The target URL.
            method:    HTTP method (GET, POST, PUT, etc.).
            params:    Query parameters.
            headers:   Additional headers (merged with defaults).
            json_data: JSON body payload.
            data:      Form-encoded body payload.
            timeout:   Per-request timeout override.

        Returns:
            An ``httpx.Response`` on success, or ``None`` when the request
            fails with a handled network / timeout error.
        """
        merged_headers = self._random_headers()
        if headers:
            merged_headers.update(headers)

        request_timeout = httpx.Timeout(timeout) if timeout else None

        try:
            response = await self.client.request(
                method=method.upper(),
                url=url,
                params=params,
                headers=merged_headers,
                json=json_data,
                data=data,
                timeout=request_timeout,
            )
            return response

        except httpx.ConnectTimeout:
            logger.warning("Connect timeout: %s", url)
            return None
        except httpx.ReadTimeout:
            logger.warning("Read timeout: %s", url)
            return None
        except httpx.ConnectError:
            logger.warning("Connection refused / DNS failure: %s", url)
            return None
        except httpx.TooManyRedirects:
            logger.warning("Too many redirects: %s", url)
            return None
        except httpx.RequestError as exc:
            logger.error("Request error for %s: %s", url, exc)
            return None
