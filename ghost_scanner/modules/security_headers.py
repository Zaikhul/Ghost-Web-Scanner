"""
Security Header Audit module.

Checks the target's HTTP response headers for the presence and correct
configuration of critical security headers recommended by OWASP.
"""

from __future__ import annotations

import logging
import re

import httpx

from ghost_scanner.reports.json_report import Finding, Severity
from ghost_scanner.utils.banner import GREEN, RED, RESET, WHITE, YELLOW
from ghost_scanner.utils.banner import section_header
from ghost_scanner.utils.http_client import HttpClient

logger = logging.getLogger("ghost_scanner.headers")


class SecurityHeaderAudit:
    """Audits the target for missing or misconfigured security headers.

    Checks:
        - Content-Security-Policy (CSP)
        - Strict-Transport-Security (HSTS)
        - X-Frame-Options
        - X-Content-Type-Options
        - Permissions-Policy
        - Referrer-Policy

    Args:
        http_client: Shared async HTTP client instance.
        target_url:  Validated target URL.
    """

    def __init__(self, http_client: HttpClient, target_url: str) -> None:
        self._http = http_client
        self._target = target_url

    async def run(self) -> list[Finding]:
        """Fetch the target and audit all security headers."""
        section_header("MODULE: SECURITY HEADER AUDIT")
        findings: list[Finding] = []

        response = await self._http.fetch(self._target)
        if response is None:
            logger.error("Target unreachable — cannot audit headers.")
            return findings

        headers = response.headers

        findings.extend(self._check_csp(headers))
        findings.extend(self._check_hsts(headers))
        findings.extend(self._check_x_frame_options(headers))
        findings.extend(self._check_x_content_type_options(headers))
        findings.extend(self._check_permissions_policy(headers))
        findings.extend(self._check_referrer_policy(headers))

        found_count = len(findings)
        if found_count == 0:
            print(f"    {GREEN}[✓] All critical security headers present.{RESET}")
        else:
            print(
                f"    {YELLOW}[!] {found_count} header issue(s) detected.{RESET}"
            )

        return findings

    # ── Individual Header Checks ─────────────────────────────────────────

    def _check_csp(self, headers: httpx.Headers) -> list[Finding]:
        """Check Content-Security-Policy presence and quality."""
        findings: list[Finding] = []
        csp = headers.get("Content-Security-Policy")

        if not csp:
            print(f"    {RED}[✗] Content-Security-Policy: MISSING{RESET}")
            findings.append(Finding(
                severity=Severity.HIGH,
                category="MISSING_HEADER",
                target_url=self._target,
                detail="Content-Security-Policy header is missing.",
                remediation=(
                    "Add a Content-Security-Policy header to mitigate XSS and "
                    "data injection attacks. Start with: "
                    "Content-Security-Policy: default-src 'self'"
                ),
            ))
            return findings

        print(f"    {GREEN}[✓] Content-Security-Policy: Present{RESET}")

        # Check for unsafe directives
        unsafe_directives = ["'unsafe-inline'", "'unsafe-eval'"]
        for directive in unsafe_directives:
            if directive in csp:
                print(
                    f"    {YELLOW}  └─ Warning: CSP contains {directive}{RESET}"
                )
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    category="MISCONFIGURED_HEADER",
                    target_url=self._target,
                    detail=f"CSP contains {directive} which weakens XSS protection.",
                    remediation=f"Remove {directive} from CSP and use nonces or hashes.",
                ))

        return findings

    def _check_hsts(self, headers: httpx.Headers) -> list[Finding]:
        """Check Strict-Transport-Security presence and max-age."""
        findings: list[Finding] = []
        hsts = headers.get("Strict-Transport-Security")

        if not hsts:
            print(f"    {RED}[✗] Strict-Transport-Security: MISSING{RESET}")
            findings.append(Finding(
                severity=Severity.HIGH,
                category="MISSING_HEADER",
                target_url=self._target,
                detail="Strict-Transport-Security (HSTS) header is missing.",
                remediation=(
                    "Add HSTS header: "
                    "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
                ),
            ))
            return findings

        print(f"    {GREEN}[✓] Strict-Transport-Security: Present{RESET}")

        # Check max-age value
        match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
        if match:
            max_age = int(match.group(1))
            if max_age < 31536000:  # Less than 1 year
                print(
                    f"    {YELLOW}  └─ Warning: max-age={max_age} "
                    f"(recommended: ≥31536000){RESET}"
                )
                findings.append(Finding(
                    severity=Severity.LOW,
                    category="MISCONFIGURED_HEADER",
                    target_url=self._target,
                    detail=f"HSTS max-age={max_age} is below the recommended 31536000 (1 year).",
                    remediation="Set max-age to at least 31536000 (1 year).",
                ))

        if "includesubdomains" not in hsts.lower():
            print(
                f"    {YELLOW}  └─ Warning: includeSubDomains not set.{RESET}"
            )
            findings.append(Finding(
                severity=Severity.LOW,
                category="MISCONFIGURED_HEADER",
                target_url=self._target,
                detail="HSTS does not include 'includeSubDomains' directive.",
                remediation="Add 'includeSubDomains' to the HSTS header.",
            ))

        return findings

    def _check_x_frame_options(self, headers: httpx.Headers) -> list[Finding]:
        """Check X-Frame-Options header."""
        xfo = headers.get("X-Frame-Options")

        if not xfo:
            print(f"    {RED}[✗] X-Frame-Options: MISSING{RESET}")
            return [Finding(
                severity=Severity.MEDIUM,
                category="MISSING_HEADER",
                target_url=self._target,
                detail="X-Frame-Options header is missing (clickjacking risk).",
                remediation="Add X-Frame-Options: DENY or SAMEORIGIN.",
            )]

        value = xfo.strip().upper()
        if value not in ("DENY", "SAMEORIGIN"):
            print(f"    {YELLOW}[!] X-Frame-Options: {xfo} (non-standard){RESET}")
            return [Finding(
                severity=Severity.LOW,
                category="MISCONFIGURED_HEADER",
                target_url=self._target,
                detail=f"X-Frame-Options has non-standard value: '{xfo}'.",
                remediation="Set to DENY or SAMEORIGIN.",
            )]

        print(f"    {GREEN}[✓] X-Frame-Options: {value}{RESET}")
        return []

    def _check_x_content_type_options(
        self, headers: httpx.Headers
    ) -> list[Finding]:
        """Check X-Content-Type-Options header."""
        xcto = headers.get("X-Content-Type-Options")

        if not xcto:
            print(f"    {RED}[✗] X-Content-Type-Options: MISSING{RESET}")
            return [Finding(
                severity=Severity.MEDIUM,
                category="MISSING_HEADER",
                target_url=self._target,
                detail="X-Content-Type-Options header is missing (MIME-sniffing risk).",
                remediation="Add X-Content-Type-Options: nosniff.",
            )]

        if "nosniff" not in xcto.lower():
            print(f"    {YELLOW}[!] X-Content-Type-Options: {xcto}{RESET}")
            return [Finding(
                severity=Severity.LOW,
                category="MISCONFIGURED_HEADER",
                target_url=self._target,
                detail=f"X-Content-Type-Options value '{xcto}' does not include 'nosniff'.",
                remediation="Set value to 'nosniff'.",
            )]

        print(f"    {GREEN}[✓] X-Content-Type-Options: nosniff{RESET}")
        return []

    def _check_permissions_policy(
        self, headers: httpx.Headers
    ) -> list[Finding]:
        """Check Permissions-Policy (formerly Feature-Policy)."""
        pp = headers.get("Permissions-Policy") or headers.get("Feature-Policy")

        if not pp:
            print(f"    {RED}[✗] Permissions-Policy: MISSING{RESET}")
            return [Finding(
                severity=Severity.LOW,
                category="MISSING_HEADER",
                target_url=self._target,
                detail="Permissions-Policy header is missing.",
                remediation=(
                    "Add Permissions-Policy to restrict browser features: "
                    "Permissions-Policy: geolocation=(), camera=(), microphone=()"
                ),
            )]

        print(f"    {GREEN}[✓] Permissions-Policy: Present{RESET}")
        return []

    def _check_referrer_policy(self, headers: httpx.Headers) -> list[Finding]:
        """Check Referrer-Policy header."""
        rp = headers.get("Referrer-Policy")

        if not rp:
            print(f"    {YELLOW}[~] Referrer-Policy: MISSING{RESET}")
            return [Finding(
                severity=Severity.LOW,
                category="MISSING_HEADER",
                target_url=self._target,
                detail="Referrer-Policy header is missing.",
                remediation=(
                    "Add Referrer-Policy: strict-origin-when-cross-origin "
                    "or no-referrer."
                ),
            )]

        print(f"    {GREEN}[✓] Referrer-Policy: {rp}{RESET}")
        return []
