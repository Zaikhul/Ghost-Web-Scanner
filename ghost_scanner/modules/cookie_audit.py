"""
Cookie Security Audit module.

Analyses session cookies for the presence of critical security flags:
HttpOnly, Secure, and SameSite — as recommended by OWASP.
"""

from __future__ import annotations

import logging
from http.cookiejar import Cookie

import httpx

from ghost_scanner.reports.json_report import Finding, Severity
from ghost_scanner.utils.banner import GREEN, RED, RESET, YELLOW
from ghost_scanner.utils.banner import section_header
from ghost_scanner.utils.http_client import HttpClient

logger = logging.getLogger("ghost_scanner.cookies")

# Cookie name patterns commonly associated with sessions
_SESSION_PATTERNS: list[str] = [
    "session", "sess", "sid", "token", "auth", "jwt",
    "phpsessid", "jsessionid", "asp.net_sessionid", "csrftoken",
    "connect.sid", "_csrf", "xsrf",
]


def _is_session_cookie(name: str) -> bool:
    """Heuristic check if a cookie name looks like a session identifier."""
    lower = name.lower()
    return any(pat in lower for pat in _SESSION_PATTERNS)


class CookieAudit:
    """Audits cookies returned by the target for security flags.

    Args:
        http_client: Shared async HTTP client instance.
        target_url:  Validated target URL.
    """

    def __init__(self, http_client: HttpClient, target_url: str) -> None:
        self._http = http_client
        self._target = target_url

    async def run(self) -> list[Finding]:
        """Fetch the target and audit all returned cookies."""
        section_header("MODULE: COOKIE SECURITY AUDIT")
        findings: list[Finding] = []

        response = await self._http.fetch(self._target)
        if response is None:
            logger.error("Target unreachable — cannot audit cookies.")
            return findings

        # Parse raw Set-Cookie headers for flag inspection
        raw_cookies = response.headers.get_list("set-cookie")

        if not raw_cookies:
            print(f"    {YELLOW}[~] No cookies set by the target.{RESET}")
            return findings

        for raw in raw_cookies:
            findings.extend(self._audit_raw_cookie(raw))

        if not findings:
            print(f"    {GREEN}[✓] All cookies have proper security flags.{RESET}")
        else:
            print(
                f"    {YELLOW}[!] {len(findings)} cookie issue(s) detected.{RESET}"
            )

        return findings

    def _audit_raw_cookie(self, raw_header: str) -> list[Finding]:
        """Audit a single raw Set-Cookie header string."""
        findings: list[Finding] = []
        parts = [p.strip() for p in raw_header.split(";")]

        # First part is name=value
        name_value = parts[0] if parts else ""
        cookie_name = name_value.split("=", 1)[0].strip()
        is_session = _is_session_cookie(cookie_name)

        directives_lower = {p.lower() for p in parts[1:]}
        directives_str = " ".join(parts[1:]).lower()

        label = f"{'SESSION ' if is_session else ''}Cookie: {cookie_name}"
        print(f"\n    {YELLOW}[*] Auditing {label}{RESET}")

        # ── HttpOnly ──
        has_httponly = any("httponly" in d for d in directives_lower)
        if not has_httponly:
            severity = Severity.HIGH if is_session else Severity.MEDIUM
            print(f"    {RED}  [✗] HttpOnly: MISSING{RESET}")
            findings.append(Finding(
                severity=severity,
                category="INSECURE_COOKIE",
                target_url=self._target,
                detail=f"{label} is missing the HttpOnly flag (XSS cookie theft risk).",
                remediation=f"Set HttpOnly flag on cookie '{cookie_name}'.",
            ))
        else:
            print(f"    {GREEN}  [✓] HttpOnly: Set{RESET}")

        # ── Secure ──
        has_secure = any("secure" in d for d in directives_lower)
        if not has_secure:
            severity = Severity.HIGH if is_session else Severity.MEDIUM
            print(f"    {RED}  [✗] Secure: MISSING{RESET}")
            findings.append(Finding(
                severity=severity,
                category="INSECURE_COOKIE",
                target_url=self._target,
                detail=(
                    f"{label} is missing the Secure flag "
                    f"(transmitted over unencrypted HTTP)."
                ),
                remediation=f"Set Secure flag on cookie '{cookie_name}'.",
            ))
        else:
            print(f"    {GREEN}  [✓] Secure: Set{RESET}")

        # ── SameSite ──
        has_samesite = "samesite" in directives_str
        if not has_samesite:
            print(f"    {YELLOW}  [~] SameSite: MISSING{RESET}")
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category="INSECURE_COOKIE",
                target_url=self._target,
                detail=f"{label} is missing the SameSite attribute (CSRF risk).",
                remediation=(
                    f"Set SameSite=Lax or SameSite=Strict on cookie '{cookie_name}'."
                ),
            ))
        else:
            # Check if set to None without Secure
            if "samesite=none" in directives_str and not has_secure:
                print(f"    {RED}  [✗] SameSite=None without Secure flag{RESET}")
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category="INSECURE_COOKIE",
                    target_url=self._target,
                    detail=(
                        f"{label} has SameSite=None but is missing the Secure flag. "
                        "Browsers will reject this cookie."
                    ),
                    remediation="When using SameSite=None, the Secure flag is mandatory.",
                ))
            else:
                print(f"    {GREEN}  [✓] SameSite: Set{RESET}")

        return findings
