"""Lightweight terminal progress reporting with a live vuln counter."""

from __future__ import annotations

import sys
from typing import Optional, TextIO


class Progress:
    """Render an in-place progress bar that also counts discovered findings.

    Works on iOS (NewTerm/zsh), macOS and Linux. Falls back to plain lines when
    stderr is not a TTY so logs stay readable.
    """

    def __init__(self, enabled: bool = True, stream: Optional[TextIO] = None,
                 width: int = 24) -> None:
        self.enabled = enabled
        self.stream = stream if stream is not None else sys.stderr
        self.width = width
        self._tty = bool(getattr(self.stream, "isatty", lambda: False)())
        self._found = 0

    def start(self, label: str) -> None:
        self._emit(label, 0, 1)

    def step(self, label: str, current: int, total: int, found: Optional[int] = None) -> None:
        if found is not None:
            self._found = found
        self._emit(label, current, total)

    def add_found(self, n: int) -> None:
        self._found += n

    def finish(self, label: str = "完成", found: Optional[int] = None) -> None:
        if found is not None:
            self._found = found
        if not self.enabled:
            return
        self._emit(label, 1, 1, done=True)
        try:
            self.stream.write("\n")
            self.stream.flush()
        except (OSError, ValueError):
            pass

    def _emit(self, label: str, current: int, total: int, done: bool = False) -> None:
        if not self.enabled:
            return
        total = max(total, 1)
        ratio = min(1.0, max(0.0, current / total))
        filled = int(self.width * ratio)
        bar = "#" * filled + "-" * (self.width - filled)
        pct = int(ratio * 100)
        line = (
            f"\r[{bar}] {pct:3d}%  {label:<28} "
            f"疑似漏洞: {self._found}"
        )
        if not self._tty and not done:
            # Non-interactive: only print meaningful steps, no carriage returns.
            line = line.lstrip("\r") + "\n"
        try:
            self.stream.write(line)
            self.stream.flush()
        except (OSError, ValueError):
            pass
