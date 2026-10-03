"""
Ghost Scanner — CLI entry point.

Usage::

    python -m ghost_scanner --target https://example.com
    python -m ghost_scanner --target example.com --no-ssl-verify --output report.json
    python -m ghost_scanner --target 10.0.0.5 --allow-private --modules recon headers cookies stress
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from ghost_scanner import __version__
from ghost_scanner.core.config import InvalidTargetError, ScanConfig
from ghost_scanner.core.engine import GhostEngine
from ghost_scanner.utils.banner import RED, RESET
from ghost_scanner.utils.ui import setup_logger


def build_parser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="ghost_scanner",
        description=(
            "Ghost Scanner v{} — Modular Defensive Web Security Auditing "
            "Framework for authorised internal infrastructure assessment."
        ).format(__version__),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Target URL to scan (e.g. https://example.com).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Per-request timeout in seconds (default: 10).",
    )
    parser.add_argument(
        "--ssl-verify",
        dest="ssl_verify",
        action="store_true",
        default=True,
        help="Enable TLS/SSL certificate verification (default).",
    )
    parser.add_argument(
        "--no-ssl-verify",
        dest="ssl_verify",
        action="store_false",
        help="Disable TLS/SSL certificate verification.",
    )
    parser.add_argument(
        "--allow-private",
        action="store_true",
        default=False,
        help="Allow scanning of private/RFC-1918 IP addresses.",
    )
    parser.add_argument(
        "--concurrency", "-c",
        type=int,
        default=50,
        help="Maximum concurrent async requests (default: 50).",
    )
    parser.add_argument(
        "--modules", "-m",
        nargs="+",
        default=["recon", "headers", "cookies"],
        choices=["recon", "headers", "cookies", "stress"],
        help="Scan modules to execute (default: recon headers cookies).",
    )
    parser.add_argument(
        "--output", "-o",
        default="",
        help="Output path for the JSON report (default: auto-generated).",
    )
    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"Ghost Scanner v{__version__}",
    )

    return parser


def main() -> None:
    """Parse arguments, build config, and launch the engine."""
    parser = build_parser()
    args = parser.parse_args()

    # Initialise logger
    setup_logger("ghost_scanner")

    # Build validated configuration
    try:
        config = ScanConfig(
            target_url=args.target,
            timeout=args.timeout,
            ssl_verify=args.ssl_verify,
            allow_private=args.allow_private,
            max_concurrency=args.concurrency,
            output_path=args.output,
            modules=args.modules,
        )
    except InvalidTargetError as exc:
        print(f"\n{RED}[ERROR] {exc}{RESET}", file=sys.stderr)
        sys.exit(1)

    # Run the engine
    engine = GhostEngine(config)
    try:
        asyncio.run(engine.run())
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Scan terminated by operator.{RESET}")
        sys.exit(130)


if __name__ == "__main__":
    main()
