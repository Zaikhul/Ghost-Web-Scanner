"""
Terminal UI utilities — ASCII banner and progress indicators.
"""

from __future__ import annotations

import sys

from ghost_scanner.core.config import ScanConfig

# Colour constants
RED = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[1;34m"
CYAN = "\033[1;36m"
WHITE = "\033[1;37m"
MAGENTA = "\033[1;35m"
RESET = "\033[0m"
BOLD = "\033[1m"


def print_banner(config: ScanConfig | None = None) -> None:
    """Print the Ghost Scanner ASCII skull banner with session info."""
    domain = config.domain if config else "Ready"
    target_ip = config.target_ip if config else "—"
    ssl_status = "ON" if (config and config.ssl_verify) else "OFF"

    print(f"{RED}{BOLD}")
    print(r"           uuuuuuu             ")
    print(r"       uu$$$$$$$$$$$uu         ")
    print(r"    uu$$$$$$$$$$$$$$$$$u       ")
    print(rf'   u$$$$$$$$$$$$$$$$$$$$u                  {CYAN}GHOST SCANNER v2.0{RED}')
    print(rf'   u$$$$$$$$$$$$$$$$$$$$$$      {GREEN}{"─" * 35}{RED}')
    print(rf'  u$$$$$$$$$$$$$$$$$$$$$$$u     {BLUE}Framework : {WHITE}Defensive Security Audit{RED}')
    print(rf'  u$$$$$$$$$$$$$$$$$$$$$$$u     {BLUE}Engine    : {GREEN}httpx / async / HTTP2{RED}')
    print(rf'  u$$$$$$"   "$$$"   "$$$$$u    {BLUE}Author    : {WHITE}Sneijderlino{RED}')
    print(rf'  "$$$$"      u$u       "$$$    {YELLOW}[github.com/Sneijderlino]{RED}')
    print(rf'   $$$u       u$u       u$$$    {GREEN}{"─" * 35}{RED}')
    print(rf'   $$$u      u$$$u      u$$$    {BLUE}TARGET    : {YELLOW}{domain}{RED}')
    print(rf'    "$$$$uu$$$   $$$uu$$$$"     {BLUE}IP        : {WHITE}{target_ip}{RED}')
    print(rf'     "$$$$$$$"   "$$$$$$$"      {BLUE}SSL VERIFY: {GREEN if ssl_status == "ON" else RED}{ssl_status}{RED}')
    print(r'       u$$$$$$$u$$$$$$$$u        ')
    print(r'        u$"$"$"$"$"$"$"u        ')
    print(r'         $$u$u$u$u$u$$         ')
    print(r'          $$$$$$$$$$$          ')
    print(r'           "$$$$$$$"           ')
    print(f"{BLUE}[ {MAGENTA}MODULAR FRAMEWORK {WHITE}| {CYAN}DEFENSIVE MODE {BLUE}]{RESET}")
    print(f"{GREEN}{'═' * 56}{RESET}")


def progress_bar(label: str, current: int, total: int) -> None:
    """Write an inline progress bar to stdout.

    Args:
        label:   Short description of the ongoing task.
        current: Current step number.
        total:   Total number of steps.
    """
    width = 25
    filled = int(width * current / total) if total > 0 else 0
    bar = f"{CYAN}█{RESET}" * filled + f"{WHITE}─{RESET}" * (width - filled)
    percent = (current / total * 100) if total > 0 else 0
    sys.stdout.write(f"\r    {WHITE}[{label}] [{percent:5.1f}%] [{bar}]{RESET}")
    sys.stdout.flush()
    if current >= total:
        sys.stdout.write("\n")


def section_header(title: str) -> None:
    """Print a visually distinct section header."""
    print(f"\n{YELLOW}{'═' * 56}")
    print(f"  {WHITE}{title}")
    print(f"{YELLOW}{'═' * 56}{RESET}")
