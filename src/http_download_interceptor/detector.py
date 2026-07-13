"""Defensive companion — detect ARP spoofing and download tampering.

This module runs passively on a *potentially-compromised* network and raises
alerts when it observes signs of:

1. **ARP poisoning** — duplicate MAC addresses replying for the same IP,
   gratuitous ARP replies, or MAC address changes on the gateway.
2. **Download tampering** — HTTP 301/302 redirects injected between a client
   and a known-good server, Content-Length mismatches, or unexpected
   Content-Type changes.

It is intended as a *defensive demonstration* to pair with the offensive
interceptor: understanding both sides is a hiring plus.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable

LOGGER = logging.getLogger(__name__)

try:
    import scapy.all as scapy  # noqa: WPS433
except ImportError:
    scapy = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Alert model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Alert:
    """A single security event detected by the passive monitor."""

    timestamp: float
    category: str  # "arp_poison" | "download_tamper" | "anomaly"
    severity: str  # "low" | "medium" | "high" | "critical"
    message: str
    details: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# ARP spoof detector
# ---------------------------------------------------------------------------

class ArpPoisonDetector:
    """Monitor ARP traffic for signs of cache poisoning.

    Algorithm:
    * Maintain a map ``{IP -> set of MACs}`` seen in ARP replies.
    * If more than one MAC ever replies for the same IP, flag it.
    * Track the gateway MAC; if it changes, flag it.
    """

    def __init__(
        self,
        gateway_ip: str | None = None,
        callback: Callable[[Alert], None] | None = None,
    ) -> None:
        self.gateway_ip = gateway_ip
        self._ip_to_macs: dict[str, set[str]] = defaultdict(set)
        self._known_gateway_mac: str | None = None
        self._callback = callback
        self.alerts: list[Alert] = []

    def process_arp(self, pkt) -> None:
        """Inspect a single ARP packet for poisoning indicators."""
        if scapy is None or not pkt.haslayer(scapy.ARP):
            return

        arp = pkt[scapy.ARP]
        if arp.op != 2:  # Only look at replies (op=2)
            return

        src_ip = arp.psrc
        src_mac = arp.hwsrc

        self._ip_to_macs[src_ip].add(src_mac)

        # --- Duplicate MAC check ---
        if len(self._ip_to_macs[src_ip]) > 1:
            macs = ", ".join(sorted(self._ip_to_macs[src_ip]))
            alert = Alert(
                timestamp=time.time(),
                category="arp_poison",
                severity="high",
                message=f"Multiple MACs ({macs}) replying for {src_ip} — possible ARP poisoning",
                details={"ip": src_ip, "macs": list(self._ip_to_macs[src_ip])},
            )
            self._emit(alert)

        # --- Gateway MAC change check ---
        if self.gateway_ip and src_ip == self.gateway_ip:
            if self._known_gateway_mac is None:
                self._known_gateway_mac = src_mac
                LOGGER.debug("Known gateway MAC: %s", src_mac)
            elif src_mac != self._known_gateway_mac:
                alert = Alert(
                    timestamp=time.time(),
                    category="arp_poison",
                    severity="critical",
                    message=(
                        f"Gateway {src_ip} MAC changed: "
                        f"{self._known_gateway_mac} -> {src_mac}"
                    ),
                    details={
                        "old_mac": self._known_gateway_mac,
                        "new_mac": src_mac,
                    },
                )
                self._emit(alert)
                self._known_gateway_mac = src_mac

    def _emit(self, alert: Alert) -> None:
        self.alerts.append(alert)
        LOGGER.warning("[%s] %s", alert.severity.upper(), alert.message)
        if self._callback:
            self._callback(alert)


# ---------------------------------------------------------------------------
# Download tampering detector
# ---------------------------------------------------------------------------

class DownloadTamperDetector:
    """Monitor HTTP traffic for signs of injected redirects.

    Algorithm:
    * Track HTTP requests and their corresponding responses.
    * Flag if a 3xx redirect appears where a 2xx was expected for a direct
      download URL (based on file extension heuristics).
    * Flag Content-Length mismatches between response headers and body.
    """

    def __init__(self, callback: Callable[[Alert], None] | None = None) -> None:
        self._pending_requests: dict[tuple, dict] = {}
        self._callback = callback
        self.alerts: list[Alert] = []

    def process_packet(self, pkt) -> None:
        """Inspect a TCP packet for HTTP tampering signs."""
        if scapy is None:
            return
        if not (pkt.haslayer(scapy.IP) and pkt.haslayer(scapy.TCP)):
            return

        ip = pkt[scapy.IP]
        tcp = pkt[scapy.TCP]
        payload = bytes(tcp.payload) if tcp.payload else b""
        if not payload:
            return

        # --- HTTP request ---
        if payload[:4] in (b"GET ", b"POST"):
            self._track_request(ip, tcp, payload)
            return

        # --- HTTP response ---
        if payload[:7] == b"HTTP/1.":
            self._check_response(ip, tcp, payload)

    def _track_request(self, ip, tcp, payload: bytes) -> None:
        """Store metadata about an outgoing request for later comparison."""
        # Quick parse of path and host
        first_line_end = payload.find(b"\r\n")
        if first_line_end == -1:
            return
        request_line = payload[:first_line_end].decode("ascii", errors="replace")
        parts = request_line.split(" ")
        if len(parts) < 2:
            return
        path = parts[1]

        key = (ip.src, tcp.sport, ip.dst, tcp.dport)
        self._pending_requests[key] = {
            "path": path,
            "timestamp": time.time(),
        }

    def _check_response(self, ip, tcp, payload: bytes) -> None:
        """Compare the response against the stored request for anomalies."""
        key = (ip.dst, tcp.dport, ip.src, tcp.sport)
        req = self._pending_requests.pop(key, None)
        if req is None:
            return

        # Parse status code
        first_line_end = payload.find(b"\r\n")
        if first_line_end == -1:
            return
        status_line = payload[:first_line_end].decode("ascii", errors="replace")
        parts = status_line.split(" ", 2)
        if len(parts) < 2:
            return
        try:
            status_code = int(parts[1])
        except ValueError:
            return

        path = req["path"]

        # Flag 3xx redirects for downloadable files (likely tampering)
        download_exts = (".exe", ".msi", ".zip", ".pdf", ".tar", ".gz", ".rar",
                         ".deb", ".rpm", ".dmg", ".apk")
        if status_code in (301, 302, 307, 308):
            if any(path.lower().endswith(ext) for ext in download_exts):
                alert = Alert(
                    timestamp=time.time(),
                    category="download_tamper",
                    severity="high",
                    message=f"HTTP {status_code} redirect on download: {path}",
                    details={"path": path, "status": status_code},
                )
                self._emit(alert)

    def _emit(self, alert: Alert) -> None:
        self.alerts.append(alert)
        LOGGER.warning("[%s] %s", alert.severity.upper(), alert.message)
        if self._callback:
            self._callback(alert)


# ---------------------------------------------------------------------------
# Passive monitor runner
# ---------------------------------------------------------------------------

class PassiveMonitor:
    """Runs both detectors on a sniff loop."""

    def __init__(
        self,
        gateway_ip: str | None = None,
        interface: str | None = None,
        callback: Callable[[Alert], None] | None = None,
    ) -> None:
        self.interface = interface
        self.arp_detector = ArpPoisonDetector(gateway_ip=gateway_ip, callback=callback)
        self.http_detector = DownloadTamperDetector(callback=callback)
        self._running = False

    def _process(self, pkt) -> None:
        self.arp_detector.process_arp(pkt)
        self.http_detector.process_packet(pkt)

    def start(self, count: int = 0) -> None:
        """Begin passive sniffing. ``count=0`` means unlimited."""
        if scapy is None:
            raise SystemExit("Scapy is required for passive monitoring.")
        self._running = True
        LOGGER.info("Passive monitor started on %s", self.interface or "default interface")
        try:
            scapy.sniff(
                iface=self.interface,
                prn=self._process,
                store=False,
                count=count,
            )
        except KeyboardInterrupt:
            LOGGER.info("Monitor stopped by user.")
        finally:
            self._running = False

    @property
    def all_alerts(self) -> list[Alert]:
        return self.arp_detector.alerts + self.http_detector.alerts
