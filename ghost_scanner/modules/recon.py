"""
Reconnaissance module — subdomain enumeration, directory brute-force,
technology fingerprinting, and IP geolocation.

Migrated from the legacy ``run_v47()`` with proper async concurrency,
typed findings, and structured error handling.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from urllib.parse import urljoin

import httpx

from ghost_scanner.reports.json_report import Finding, Severity
from ghost_scanner.utils.banner import CYAN, GREEN, RED, RESET, WHITE, YELLOW
from ghost_scanner.utils.banner import progress_bar, section_header
from ghost_scanner.utils.http_client import HttpClient

logger = logging.getLogger("ghost_scanner.recon")

# ── Default wordlists ────────────────────────────────────────────────────────

SUBDOMAIN_WORDLIST: list[str] = [
    "www", "mail", "dev", "staging", "admin", "api", "test",
    "webmail", "blog", "vpn", "cloud", "cpanel", "portal",
    "db", "ftp", "ns1", "ns2", "cdn", "app", "shop",
]

DIRECTORY_WORDLIST: list[str] = [
    "admin", "login", ".env", ".git/config", "config.php.bak",
    "backup.zip", "phpinfo.php", "server-status", "robots.txt",
    "wp-admin", "wp-login.php", ".htaccess", "web.config",
    "sitemap.xml", "api", "v1/api", "swagger", "graphql",
    ".well-known/security.txt", "debug",
]


class ReconModule:
    """Performs passive and active reconnaissance on the target.

    Args:
        http_client: Shared async HTTP client instance.
        target_url:  Validated target URL.
        domain:      Extracted hostname / netloc.
        target_ip:   Resolved IPv4 of the target.
    """

    def __init__(
        self,
        http_client: HttpClient,
        target_url: str,
        domain: str,
        target_ip: str,
    ) -> None:
        self._http = http_client
        self._target = target_url
        self._domain = domain
        self._target_ip = target_ip
        self._findings: list[Finding] = []

    # ── Public API ────────────────────────────────────────────────────────

    async def run_full(self) -> list[Finding]:
        """Execute the full recon pipeline and return all findings."""
        section_header("MODULE: RECONNAISSANCE")

        await self._geolocate_ip()
        await self._fingerprint_tech()
        await self._enumerate_subdomains()
        await self._brute_directories()

        logger.info(
            "Recon complete — %d findings collected.", len(self._findings)
        )
        return self._findings

    # ── IP Geolocation ────────────────────────────────────────────────────

    async def _geolocate_ip(self) -> None:
        """Query ip-api.com for target IP geolocation."""
        print(f"\n  {CYAN}[*] Phase 1: IP Geolocation...{RESET}")

        response = await self._http.fetch(
            f"http://ip-api.com/json/{self._target_ip}",
            timeout=5.0,
        )
        if response is None:
            logger.warning("Geolocation API unreachable.")
            return

        try:
            data = response.json()
            if data.get("status") == "success":
                location = (
                    f"{data.get('city', '?')}, {data.get('country', '?')} "
                    f"({data.get('as', 'Unknown ASN')})"
                )
                self._findings.append(Finding(
                    severity=Severity.INFO,
                    category="TECH_INFO",
                    target_url=self._target,
                    detail=f"Server location: {location}",
                ))
                print(f"    {GREEN}[+] Location: {location}{RESET}")
        except (ValueError, KeyError) as exc:
            logger.warning("Failed to parse geolocation response: %s", exc)

    # ── Technology Fingerprinting ─────────────────────────────────────────

    async def _fingerprint_tech(self) -> None:
        """Detect WAF, web server, CMS, and backend technology."""
        print(f"\n  {CYAN}[*] Phase 2: Technology Fingerprinting...{RESET}")

        response = await self._http.fetch(self._target)
        if response is None:
            logger.warning("Target unreachable for fingerprinting.")
            return

        headers_lower = str(response.headers).lower()

        # ── WAF Detection ──
        waf_signatures: dict[str, str] = {
            "cloudflare": "Cloudflare WAF",
            "mod_security": "ModSecurity",
            "sucuri": "Sucuri CloudProxy",
            "akamai": "Akamai WAF",
            "incapsula": "Imperva Incapsula",
            "aws-waf": "AWS WAF",
        }
        for signature, waf_name in waf_signatures.items():
            if signature in headers_lower:
                self._findings.append(Finding(
                    severity=Severity.INFO,
                    category="TECH_INFO",
                    target_url=self._target,
                    detail=f"WAF detected: {waf_name}",
                ))
                print(f"    {YELLOW}[!] WAF Detected: {waf_name}{RESET}")
                break

        # ── Server header ──
        server = response.headers.get("Server", "Unknown")
        powered_by = response.headers.get("X-Powered-By", "")
        self._findings.append(Finding(
            severity=Severity.INFO,
            category="TECH_INFO",
            target_url=self._target,
            detail=f"Server: {server}"
                   + (f" | Powered by: {powered_by}" if powered_by else ""),
        ))
        print(f"    {WHITE}[i] Server: {server}{RESET}")
        if powered_by:
            print(f"    {WHITE}[i] X-Powered-By: {powered_by}{RESET}")

        # ── CMS Detection (basic) ──
        body = response.text.lower()
        cms_signatures: dict[str, str] = {
            "wp-content": "WordPress",
            "/joomla": "Joomla",
            "drupal": "Drupal",
            "shopify": "Shopify",
            "wix.com": "Wix",
        }
        for sig, cms in cms_signatures.items():
            if sig in body:
                self._findings.append(Finding(
                    severity=Severity.INFO,
                    category="TECH_INFO",
                    target_url=self._target,
                    detail=f"CMS detected: {cms}",
                ))
                print(f"    {GREEN}[+] CMS: {cms}{RESET}")

    # ── Subdomain Enumeration ─────────────────────────────────────────────

    async def _enumerate_subdomains(self) -> None:
        """Async concurrent subdomain discovery via DNS + HTTP probing."""
        section_header("SUBDOMAIN ENUMERATION")
        base_domain = self._domain.removeprefix("www.")

        async def _check_sub(sub: str) -> Finding | None:
            fqdn = f"{sub}.{base_domain}"
            try:
                loop = asyncio.get_running_loop()
                ip = await loop.run_in_executor(None, socket.gethostbyname, fqdn)
            except socket.gaierror:
                return None

            response = await self._http.fetch(f"http://{fqdn}", timeout=5.0)
            status = f"HTTP {response.status_code}" if response else "No HTTP"
            detail = f"{fqdn} → {ip} [{status}]"
            print(f"    {GREEN}[+] {detail}{RESET}")
            return Finding(
                severity=Severity.INFO,
                category="SUBDOMAIN",
                target_url=f"http://{fqdn}",
                detail=detail,
            )

        tasks = [_check_sub(s) for s in SUBDOMAIN_WORDLIST]
        results = await asyncio.gather(*tasks)

        for i, result in enumerate(results):
            progress_bar("Subdomains", i + 1, len(SUBDOMAIN_WORDLIST))
            if result:
                self._findings.append(result)

        print(
            f"    {WHITE}[i] Discovered "
            f"{sum(1 for r in results if r)} subdomains.{RESET}"
        )

    # ── Directory Brute-Force ─────────────────────────────────────────────

    async def _brute_directories(self) -> None:
        """Concurrent directory brute-force with status-code classification."""
        section_header("DIRECTORY BRUTE-FORCE")

        async def _check_path(path: str) -> Finding | None:
            url = urljoin(self._target.rstrip("/") + "/", path)
            response = await self._http.fetch(url, timeout=5.0)
            if response is None:
                return None
            if response.status_code in (200, 403, 405, 301, 302):
                is_sensitive = response.status_code == 200
                severity = Severity.HIGH if is_sensitive else Severity.LOW
                category = "SENSITIVE_DIR" if is_sensitive else "DIRECTORY"
                detail = f"{url} [{response.status_code}]"
                colour = RED if is_sensitive else YELLOW
                print(f"    {colour}[{'!!!' if is_sensitive else '+'}] {detail}{RESET}")
                return Finding(
                    severity=severity,
                    category=category,
                    target_url=url,
                    detail=detail,
                    remediation="Restrict access or remove from public exposure."
                    if is_sensitive
                    else "",
                )
            return None

        tasks = [_check_path(p) for p in DIRECTORY_WORDLIST]
        results = await asyncio.gather(*tasks)

        for i, result in enumerate(results):
            progress_bar("Directories", i + 1, len(DIRECTORY_WORDLIST))
            if result:
                self._findings.append(result)

        print(
            f"    {WHITE}[i] Brute-force complete — "
            f"{sum(1 for r in results if r)} paths found.{RESET}"
        )
