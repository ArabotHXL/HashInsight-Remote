"""HashInsight Remote entrypoint.

This wrapper improves UX for packaged binaries:
- Writes crash logs to a predictable local path
- Keeps the console open on fatal errors (when a console is present)

This does NOT change any privacy constraints; miner IP/credentials remain local-only.
"""

from __future__ import annotations

import os
import sys
import time
import traceback
from pathlib import Path

from pickaxe_app.main import run


def _logs_dir() -> Path:
    base = os.getenv("LOCALAPPDATA") or os.getenv("APPDATA") or str(Path.home())
    d = Path(base) / "HashInsightRemote" / "logs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _write_crash_log(text: str) -> Path:
    p = _logs_dir() / f"crash_{int(time.time())}.log"
    p.write_text(text, encoding="utf-8", errors="ignore")
    return p


def _maybe_message_box(title: str, message: str) -> None:
    if not sys.platform.startswith("win"):
        return
    try:
        import ctypes  # type: ignore

        ctypes.windll.user32.MessageBoxW(0, message, title, 0x10)  # MB_ICONERROR
    except Exception:
        # Best-effort; console/log file still captures the error.
        pass


def main() -> None:
    try:
        run()
    except Exception:
        tb = traceback.format_exc()
        path = _write_crash_log(tb)
        last_line = tb.strip().splitlines()[-1] if tb.strip() else "(no traceback)"
        console_msg = (
            "HashInsight Remote crashed.\n"
            f"Crash log: {path}\n\n"
            f"{last_line}\n"
        )
        try:
            print(console_msg)
        except Exception:
            pass

        _maybe_message_box("HashInsight Remote crashed", f"Crash log written to:\n{path}")

        # If launched from a console, keep it open so the operator can read the message.
        try:
            if sys.stdout is not None and sys.stdout.isatty():
                input("Press Enter to exit...")
        except Exception:
            pass

        raise


if __name__ == "__main__":
    main()
