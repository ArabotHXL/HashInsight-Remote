"""Logging helpers for Pickaxe Collector.

This module is intentionally conservative:
- Avoids duplicate handlers (common when uvicorn reloads).
- Ensures BOTH file + console handlers exist.
- Makes uvicorn.access log to the same file (for easier debugging).
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional


def _find_rotating_file_handler(logger: logging.Logger, log_path: Path) -> Optional[RotatingFileHandler]:
    for h in logger.handlers:
        if isinstance(h, RotatingFileHandler):
            # RotatingFileHandler keeps the path in baseFilename
            try:
                if Path(getattr(h, "baseFilename", "")).resolve() == log_path.resolve():
                    return h
            except Exception:
                continue
    return None


def _find_console_handler(logger: logging.Logger) -> Optional[logging.StreamHandler]:
    for h in logger.handlers:
        # FileHandler is a StreamHandler subclass; exclude it so we don't mistake file handler as console.
        if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler):
            return h
    return None


def setup_logging(log_dir: Path, level: int = logging.INFO) -> Path:
    """Configure logging.

    Returns the log file path.
    """

    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "pickaxe.log"

    fmt = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    root = logging.getLogger()
    root.setLevel(level)

    # File handler (rotate ~10MB, keep 5 backups)
    fh = _find_rotating_file_handler(root, log_file)
    if fh is None:
        fh = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        fh.setLevel(level)
        fh.setFormatter(fmt)
        root.addHandler(fh)

    # Console handler
    ch = _find_console_handler(root)
    if ch is None:
        ch = logging.StreamHandler()
        ch.setLevel(level)
        ch.setFormatter(fmt)
        root.addHandler(ch)

    # Uvicorn loggers: let them propagate to root
    for lname in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        lg = logging.getLogger(lname)
        lg.setLevel(level)
        lg.propagate = True
        # Remove handlers uvicorn might have added, to avoid duplicates
        lg.handlers = []

    return log_file
