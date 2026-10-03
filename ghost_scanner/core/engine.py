"""
Ghost Scanner — Core Engine.

Orchestrates all scan modules, manages the shared HTTP client lifecycle,
collects findings, and triggers report generation.
"""

from __future__ import annotations

import logging

from ghost_scanner.core.config import ScanConfig
from ghost_scanner.modules.cookie_audit import CookieAudit
from ghost_scanner.modules.recon import ReconModule
from ghost_scanner.modules.security_headers import SecurityHeaderAudit
from ghost_scanner.modules.stress_test import StressTestModule
from ghost_scanner.reports.json_report import ScanReport
from ghost_scanner.utils.banner import (
    GREEN,
    RED,
    RESET,
    WHITE,
    YELLOW,
    print_banner,
    section_header,
)
from ghost_scanner.utils.http_client import HttpClient

logger = logging.getLogger("ghost_scanner.engine")


class GhostEngine:
    """Main scan orchestrator.

    Wires together configuration, HTTP client, scan modules, and reporting.

    Usage::

        config = ScanConfig(target_url="https://example.com")
        engine = GhostEngine(config)
        await engine.run()

    Args:
        config: Validated scan session configuration.
    """

    def __init__(self, config: ScanConfig) -> None:
        self._config = config

    async def run(self) -> None:
        """Execute the full scan pipeline."""
        print_banner(self._config)

        report = ScanReport(
            target_url=self._config.target_url,
            domain=self._config.domain,
            target_ip=self._config.target_ip,
        )

        async with HttpClient(
            timeout=self._config.timeout,
            ssl_verify=self._config.ssl_verify,
            max_connections=self._config.max_concurrency,
        ) as http:
            # ── Recon Module ──────────────────────────────────────────
            if "recon" in self._config.modules:
                try:
                    recon = ReconModule(
                        http_client=http,
                        target_url=self._config.target_url,
                        domain=self._config.domain,
                        target_ip=self._config.target_ip,
                    )
                    findings = await recon.run_full()
                    report.add_all(findings)
                except Exception as exc:
                    logger.error("Recon module failed: %s", exc)

            # ── Security Header Audit ─────────────────────────────────
            if "headers" in self._config.modules:
                try:
                    header_audit = SecurityHeaderAudit(
                        http_client=http,
                        target_url=self._config.target_url,
                    )
                    findings = await header_audit.run()
                    report.add_all(findings)
                except Exception as exc:
                    logger.error("Security header audit failed: %s", exc)

            # ── Cookie Audit ──────────────────────────────────────────
            if "cookies" in self._config.modules:
                try:
                    cookie_audit = CookieAudit(
                        http_client=http,
                        target_url=self._config.target_url,
                    )
                    findings = await cookie_audit.run()
                    report.add_all(findings)
                except Exception as exc:
                    logger.error("Cookie audit failed: %s", exc)

            # ── Stress Test (requires explicit opt-in) ────────────────
            if "stress" in self._config.modules:
                try:
                    stress = StressTestModule(
                        http_client=http,
                        target_url=self._config.target_url,
                        concurrency=self._config.max_concurrency,
                    )
                    findings = await stress.run(authorized_by_admin=True)
                    report.add_all(findings)
                except Exception as exc:
                    logger.error("Stress test module failed: %s", exc)

        # ── Report ────────────────────────────────────────────────────
        self._print_summary(report)
        output = report.export_json(self._config.output_path or None)
        print(f"\n    {GREEN}[✓] JSON report saved: {output.resolve()}{RESET}")

    @staticmethod
    def _print_summary(report: ScanReport) -> None:
        """Print a terminal summary of all findings."""
        section_header("SCAN SUMMARY")
        risk = report.calculate_risk()
        counts = report.summary_counts()

        risk_colour = RED if risk > 70 else YELLOW if risk > 30 else GREEN
        print(f"    {WHITE}Risk Score    : {risk_colour}{risk}%{RESET}")
        print(f"    {WHITE}Total Findings: {len(report.findings)}{RESET}")

        for severity, count in counts.items():
            if count > 0:
                colour = RED if severity in ("CRITICAL", "HIGH") else YELLOW
                print(f"    {colour}  {severity}: {count}{RESET}")

        if report.findings:
            print(f"\n    {WHITE}Top Issues:{RESET}")
            for f in report.findings[:10]:
                severity_colour = (
                    RED if f.severity.value in ("CRITICAL", "HIGH") else YELLOW
                )
                print(
                    f"    {severity_colour}[{f.severity.value}] "
                    f"{f.category}: {f.detail[:80]}{RESET}"
                )
            remaining = len(report.findings) - 10
            if remaining > 0:
                print(f"    {WHITE}  ... and {remaining} more findings.{RESET}")
