"""
Structured logging configuration for Ghost Scanner.

Replaces bare print() calls with Python's ``logging`` module,
providing log levels, timestamps, and optional file output.
"""

from __future__ import annotations

import logging
import sys


# ANSI colour codes for terminal output
_COLOURS: dict[int, str] = {
    logging.DEBUG: "\033[1;36m",      # Cyan
    logging.INFO: "\033[1;32m",       # Green
    logging.WARNING: "\033[1;33m",    # Yellow
    logging.ERROR: "\033[1;31m",      # Red
    logging.CRITICAL: "\033[1;35m",   # Magenta
}
_RESET = "\033[0m"


class ColouredFormatter(logging.Formatter):
    """Formatter that adds ANSI colours based on log level."""

    def __init__(self, fmt: str | None = None, datefmt: str | None = None) -> None:
        super().__init__(fmt=fmt, datefmt=datefmt)

    def format(self, record: logging.LogRecord) -> str:
        colour = _COLOURS.get(record.levelno, "")
        record.msg = f"{colour}{record.msg}{_RESET}"
        return super().format(record)


def setup_logger(
    name: str = "ghost_scanner",
    *,
    level: int = logging.INFO,
    log_file: str | None = None,
) -> logging.Logger:
    """Create and configure a named logger.

    Args:
        name:     Logger name (dot-separated namespace).
        level:    Minimum log level.
        log_file: Optional file path for persistent log output.

    Returns:
        A configured ``logging.Logger`` instance.
    """
    logger = logging.getLogger(name)

    # Avoid duplicate handlers on repeated calls
    if logger.handlers:
        return logger

    logger.setLevel(level)

    # --- Console handler (coloured) ---
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(level)
    console.setFormatter(ColouredFormatter(
        fmt="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    ))
    logger.addHandler(console)

    # --- File handler (plain text, optional) ---
    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(level)
        fh.setFormatter(logging.Formatter(
            fmt="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        logger.addHandler(fh)

    return logger
