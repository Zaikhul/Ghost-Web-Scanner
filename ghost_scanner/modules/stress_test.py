"""
Load Resilience / Stress Test module (refactored V60).

An authorized internal stress-testing engine for validating load balancers,
WAF rate-limiting rules, and infrastructure breaking points.

This module includes a mandatory safety gate — it will NOT execute unless
``authorized_by_admin=True`` is explicitly passed.
"""

from __future__ import annotations

import asyncio
import datetime
import logging
import sys
import time

from ghost_scanner.reports.json_report import Finding, Severity
from ghost_scanner.utils.banner import CYAN, GREEN, RED, RESET, WHITE, YELLOW
from ghost_scanner.utils.banner import section_header
from ghost_scanner.utils.http_client import HttpClient

logger = logging.getLogger("ghost_scanner.stress_test")


class StressTestUnauthorizedError(Exception):
    """Raised when the stress test is invoked without explicit authorisation."""


class StressTestModule:
    """Load-resilience stress tester for authorized internal infrastructure.

    Features over the legacy V60:
        - Mandatory ``authorized_by_admin`` safety gate.
        - Configurable concurrency, duration, and request delay.
        - Graceful shutdown via ``asyncio.Event`` (no raw KeyboardInterrupt).
        - Uses shared ``httpx.AsyncClient`` for connection pool efficiency.
        - Real-time metrics and a structured ``Finding`` summary.

    Args:
        http_client:         Shared async HTTP client.
        target_url:          Validated target URL.
        concurrency:         Number of concurrent workers (default: 50).
        duration_seconds:    Maximum test duration in seconds (default: 30).
        delay_between_reqs:  Delay between requests per worker in seconds
                             (default: 0.05 → ~ 20 req/s per worker).
    """

    def __init__(
        self,
        http_client: HttpClient,
        target_url: str,
        *,
        concurrency: int = 50,
        duration_seconds: int = 30,
        delay_between_reqs: float = 0.05,
    ) -> None:
        self._http = http_client
        self._target = target_url
        self._concurrency = min(concurrency, 200)  # Hard cap
        self._duration = min(duration_seconds, 300)  # Hard cap: 5 minutes
        self._delay = max(delay_between_reqs, 0.01)  # Minimum politeness

        # Metrics
        self._total_requests = 0
        self._successful = 0
        self._failed = 0
        self._stop_event = asyncio.Event()

    # ── Safety Gate ───────────────────────────────────────────────────────

    @staticmethod
    def safety_check(*, authorized_by_admin: bool = False) -> None:
        """Validate that the operator has explicitly authorised this test.

        This function MUST be called before ``run()``. If
        ``authorized_by_admin`` is not ``True``, execution is halted.

        Raises:
            StressTestUnauthorizedError: If authorisation flag is not set.
        """
        if not authorized_by_admin:
            raise StressTestUnauthorizedError(
                "Stress test BLOCKED: 'authorized_by_admin=True' is required.\n"
                "This module is restricted to authorized internal infrastructure "
                "resilience testing only. Pass the flag explicitly to confirm."
            )

    # ── Public API ────────────────────────────────────────────────────────

    async def run(self, *, authorized_by_admin: bool = False) -> list[Finding]:
        """Execute the stress test.

        Args:
            authorized_by_admin: Must be ``True`` to proceed.

        Returns:
            A single-element list containing the summary ``Finding``.
        """
        self.safety_check(authorized_by_admin=authorized_by_admin)

        section_header("MODULE: LOAD RESILIENCE TEST")
        print(f"    {CYAN}[*] Target     : {self._target}{RESET}")
        print(f"    {CYAN}[*] Workers    : {self._concurrency}{RESET}")
        print(f"    {CYAN}[*] Duration   : {self._duration}s{RESET}")
        print(f"    {CYAN}[*] Delay/req  : {self._delay}s{RESET}")
        print(f"    {YELLOW}[!] Press Ctrl+C for graceful shutdown.{RESET}\n")

        start = time.monotonic()

        # Schedule workers + timer
        workers = [
            asyncio.create_task(self._worker(i))
            for i in range(self._concurrency)
        ]
        timer = asyncio.create_task(self._duration_timer())

        try:
            await asyncio.gather(timer, *workers)
        except asyncio.CancelledError:
            pass
        except KeyboardInterrupt:
            logger.info("Graceful shutdown initiated by operator.")
            self._stop_event.set()

        # Cancel remaining workers
        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

        elapsed = time.monotonic() - start
        rps = self._total_requests / elapsed if elapsed > 0 else 0

        # Summary
        print(f"\n    {GREEN}{'─' * 40}{RESET}")
        print(f"    {WHITE}Total Requests : {self._total_requests}{RESET}")
        print(f"    {WHITE}Successful     : {self._successful}{RESET}")
        print(f"    {WHITE}Failed         : {self._failed}{RESET}")
        print(f"    {WHITE}Duration       : {elapsed:.2f}s{RESET}")
        print(f"    {WHITE}Avg RPS        : {rps:.1f} req/s{RESET}")
        print(f"    {GREEN}{'─' * 40}{RESET}")

        error_rate = (self._failed / self._total_requests * 100) if self._total_requests else 0
        severity = Severity.INFO
        if error_rate > 50:
            severity = Severity.HIGH
        elif error_rate > 20:
            severity = Severity.MEDIUM

        return [Finding(
            severity=severity,
            category="STRESS_TEST",
            target_url=self._target,
            detail=(
                f"Load test completed: {self._total_requests} requests in "
                f"{elapsed:.2f}s ({rps:.1f} req/s). "
                f"Success: {self._successful}, Failed: {self._failed} "
                f"(Error rate: {error_rate:.1f}%)."
            ),
            remediation=(
                "Review server logs for errors under load. "
                "Tune WAF rate-limiting and load balancer health checks."
            ),
        )]

    # ── Internal Workers ──────────────────────────────────────────────────

    async def _worker(self, worker_id: int) -> None:
        """Single worker loop sending requests until stopped."""
        while not self._stop_event.is_set():
            response = await self._http.fetch(
                self._target, method="GET", timeout=5.0
            )
            self._total_requests += 1
            if response and response.status_code < 500:
                self._successful += 1
            else:
                self._failed += 1

            # Real-time counter (print every 100 requests from worker 0)
            if worker_id == 0 and self._total_requests % 100 == 0:
                sys.stdout.write(
                    f"\r    {CYAN}[LIVE] Requests: {self._total_requests} | "
                    f"OK: {self._successful} | Fail: {self._failed}{RESET}"
                )
                sys.stdout.flush()

            await asyncio.sleep(self._delay)

    async def _duration_timer(self) -> None:
        """Timer that signals stop after the configured duration."""
        try:
            await asyncio.sleep(self._duration)
        finally:
            self._stop_event.set()
