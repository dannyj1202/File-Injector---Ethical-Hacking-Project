"""Live terminal dashboard for monitoring intercepted downloads.

This module provides a lightweight, curses-like TUI (without the ``curses``
dependency) that displays:

* A scrolling log of intercepted HTTP requests and their redirect targets.
* Live counters (requests matched, responses replaced, uptime).
* Colour-coded severity indicators.

It can be used as a callback for :class:`interceptor.PacketHandler` or
:class:`detector.PassiveMonitor` to give the operator real-time visibility.

If the terminal doesn't support ANSI, the TUI degrades gracefully to plain
text logging.
"""

from __future__ import annotations

import json
import os
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

# ANSI escape helpers (no external dependency)
_BOLD = "\033[1m"
_RED = "\033[91m"
_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_CYAN = "\033[96m"
_RESET = "\033[0m"
_CLEAR = "\033[2J"
_HOME = "\033[H"

# Severity colours
_SEV_COLORS = {
    "critical": _RED,
    "high": _RED,
    "medium": _YELLOW,
    "low": _GREEN,
    "info": _CYAN,
}


def _supports_ansi() -> bool:
    """Heuristic: does this terminal support ANSI escapes?"""
    if os.getenv("NO_COLOR"):
        return False
    if os.getenv("FORCE_COLOR"):
        return True
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


# ---------------------------------------------------------------------------
# Event record
# ---------------------------------------------------------------------------

@dataclass
class EventRecord:
    """A single displayable event for the TUI."""

    timestamp: float
    category: str
    message: str
    severity: str = "info"
    details: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

class LiveDashboard:
    """Scrolling terminal dashboard for real-time event monitoring.

    Usage::

        dashboard = LiveDashboard()
        dashboard.start()

        # ... in the interceptor callback ...
        dashboard.add_event("intercept", "high",
                            "GET /evil.exe -> 301 -> http://lab/payloads/eicar.com")

        # ... on exit ...
        dashboard.stop()
    """

    max_events: int = 50
    refresh_interval: float = 1.0

    def __init__(self, use_json_log: bool = False) -> None:
        self._events: deque[EventRecord] = deque(maxlen=self.max_events)
        self._use_json = use_json_log
        self._ansi = _supports_ansi()
        self._start_time: float = 0.0
        self._counters: dict[str, int] = {
            "matched": 0,
            "replaced": 0,
            "alerts": 0,
        }
        self._running = False

    def start(self) -> None:
        """Clear the screen and draw the initial frame."""
        self._start_time = time.time()
        self._running = True
        if self._ansi:
            sys.stdout.write(_CLEAR + _HOME)
            sys.stdout.flush()

    def stop(self) -> None:
        """Final render on exit."""
        self._running = False
        self._render(final=True)

    # ------------------------------------------------------------------
    # Public API — callable from interceptor / detector callbacks
    # ------------------------------------------------------------------

    def add_event(
        self,
        category: str,
        severity: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Append an event to the live display."""
        rec = EventRecord(
            timestamp=time.time(),
            category=category,
            message=message,
            severity=severity,
            details=details or {},
        )
        self._events.append(rec)

        if category == "intercept":
            self._counters["replaced"] += 1
        elif category == "match":
            self._counters["matched"] += 1
        elif category in ("arp_poison", "download_tamper", "anomaly"):
            self._counters["alerts"] += 1

        # Structured JSON log line (for piping to jq, ELK, etc.)
        if self._use_json:
            log_line = json.dumps({
                "ts": rec.timestamp,
                "cat": rec.category,
                "sev": rec.severity,
                "msg": rec.message,
                "details": rec.details,
            })
            sys.stderr.write(log_line + "\n")
            sys.stderr.flush()

        self._render()

    # ------------------------------------------------------------------
    # Internal rendering
    # ------------------------------------------------------------------

    def _render(self, final: bool = False) -> None:
        """Redraw the dashboard."""
        uptime = time.time() - self._start_time
        mins, secs = divmod(int(uptime), 60)

        lines: list[str] = []

        # Header
        if self._ansi:
            lines.append(_BOLD + _CYAN)
        lines.append("=" * 70)
        lines.append("  HTTP Download Interceptor — Live Dashboard")
        lines.append(f"  Uptime: {mins}m {secs}s  |  "
                      f"Matched: {self._counters['matched']}  |  "
                      f"Replaced: {self._counters['replaced']}  |  "
                      f"Alerts: {self._counters['alerts']}")
        lines.append("=" * 70)
        if self._ansi:
            lines.append(_RESET)

        # Events (newest at bottom)
        if self._events:
            lines.append("")
            for ev in self._events:
                ts = time.strftime("%H:%M:%S", time.localtime(ev.timestamp))
                sev = ev.severity.upper()
                if self._ansi:
                    color = _SEV_COLORS.get(sev.lower(), "")
                    lines.append(f"  {ts}  [{color}{sev}{_RESET}]  {ev.message}")
                else:
                    lines.append(f"  {ts}  [{sev}]  {ev.message}")
        else:
            lines.append("")
            lines.append("  Waiting for events...")

        lines.append("")
        if final:
            lines.append("  Dashboard stopped.")
        else:
            lines.append("  Ctrl+C to stop.")

        # Draw
        if self._ansi and not final:
            sys.stdout.write(_HOME)
            # Fill screen to avoid artefacts
            term_height = _get_terminal_height()
            while len(lines) < term_height:
                lines.append("")
            sys.stdout.write("\n".join(lines[:term_height]))
            sys.stdout.write("\n")
            sys.stdout.flush()
        else:
            # Plain fallback — just append
            for line in lines:
                print(line)

    # ------------------------------------------------------------------
    # JSON logger interface (for interceptor.PacketHandler.json_logger)
    # ------------------------------------------------------------------

    def json_log(self, record: dict) -> None:
        """Callable that matches the ``json_logger`` signature expected by
        :class:`interceptor.PacketHandler`."""
        self.add_event(
            category=record.get("event", "unknown"),
            severity="medium",
            message=(
                f"{record.get('original_path', '?')} -> "
                f"301 -> {record.get('redirect_url', '?')}"
            ),
            details=record,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_terminal_height() -> int:
    """Return the terminal height in rows, defaulting to 40."""
    try:
        return os.get_terminal_size().lines
    except (ValueError, OSError):
        return 40
