"""Command-line interface with subcommands.

Provides a clean ``click``-style interface (using ``argparse`` to stay
dependency-free) with the following subcommands:

* ``intercept`` — start the ARP spoof + NFQUEUE interception.
* ``detect``    — run the defensive passive monitor.
* ``serve``     — spin up a simple HTTP server for the EICAR test file.
* ``eicar``     — write the EICAR test file to a path.

The operator **must** pass ``--i-am-authorized`` AND the target must be in an
RFC 1918 range (or ``--allow-public`` + confirmation) for ``intercept`` and
``detect`` to proceed.
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import signal
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .http_rewrite import build_eicar_redirect

LOGGER = logging.getLogger("http_download_interceptor")

# ---------------------------------------------------------------------------
# Banners & constants
# ---------------------------------------------------------------------------

BANNER = r"""
+----------------------------------------------------------------------+
|          HTTP Download Interceptor  v{version}                        |
|          AUTHORIZED LAB USE ONLY                                      |
+----------------------------------------------------------------------+
""".format(version=__version__)

DISCLAIMER = """
LEGAL / ETHICAL NOTICE
  This tool performs man-in-the-middle interception of HTTP traffic.
  Running it against networks you do not own or lack written authorization
  to test is ILLEGAL in most jurisdictions.
  You are solely responsible for how you use it.
  Use it ONLY in a lab or an authorized engagement.
"""

EICAR_STRING = (
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"
    "-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)


# ---------------------------------------------------------------------------
# Root parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Construct the top-level argument parser."""
    parser = argparse.ArgumentParser(
        prog="http-download-interceptor",
        description="Educational HTTP download interceptor for authorized lab use.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable DEBUG-level logging.")
    parser.add_argument("--log-json", action="store_true",
                        help="Emit structured JSON log lines to stderr.")

    sub = parser.add_subparsers(dest="command", help="Available commands")

    # --- intercept ---
    p_intercept = sub.add_parser("intercept", help="Start ARP spoof + HTTP interception.")
    p_intercept.add_argument("-t", "--target", required=True,
                             help="Victim IP address.")
    p_intercept.add_argument("-g", "--gateway", default=None,
                             help="Gateway IP (auto-detected if omitted).")
    p_intercept.add_argument("-i", "--interface", default=None,
                             help="Network interface (auto-detected if omitted).")
    p_intercept.add_argument("-c", "--config", default="config/rules.yaml",
                             help="Path to rules YAML/JSON (default: config/rules.yaml).")
    p_intercept.add_argument("--queue-num", type=int, default=0,
                             help="NFQUEUE queue number (default: 0).")
    p_intercept.add_argument("--dry-run", action="store_true",
                             help="Log what would be replaced without modifying packets.")
    p_intercept.add_argument("--no-tui", action="store_true",
                             help="Disable the live TUI dashboard.")
    p_intercept.add_argument("--i-am-authorized", action="store_true", required=True,
                             help="Confirm you are authorized to test this network.")
    p_intercept.add_argument("--allow-public", action="store_true",
                             help="Allow non-RFC1918 target (requires second confirmation).")

    # --- detect ---
    p_detect = sub.add_parser("detect", help="Run the defensive passive monitor.")
    p_detect.add_argument("-i", "--interface", default=None,
                          help="Network interface to sniff on.")
    p_detect.add_argument("-g", "--gateway", default=None,
                          help="Known gateway IP for ARP-change detection.")
    p_detect.add_argument("--count", type=int, default=0,
                          help="Number of packets to capture (0 = unlimited).")
    p_detect.add_argument("--i-am-authorized", action="store_true", required=True,
                          help="Confirm you are authorized to monitor this network.")

    # --- serve ---
    p_serve = sub.add_parser("serve", help="Start a lab HTTP server with the EICAR file.")
    p_serve.add_argument("--port", type=int, default=8000,
                         help="Port to listen on (default: 8000).")
    p_serve.add_argument("--dir", default=".",
                         help="Directory to serve from (default: cwd).")
    p_serve.add_argument("--i-am-authorized", action="store_true", required=True,
                         help="Confirm you are authorized.")

    # --- eicar ---
    p_eicar = sub.add_parser("eicar", help="Write the EICAR test file to disk.")
    p_eicar.add_argument("output", nargs="?", default="eicar.com",
                         help="Output path (default: eicar.com).")

    return parser


# ---------------------------------------------------------------------------
# Authorization gate
# ---------------------------------------------------------------------------

def _check_authorization(target_ip: str | None, allow_public: bool) -> None:
    """Enforce RFC1918 restriction + interactive confirmation."""
    if target_ip is None:
        return

    addr = ipaddress.ip_address(target_ip)
    if not addr.is_private:
        if not allow_public:
            LOGGER.error(
                "Target %s is NOT in a private RFC 1918 range.\n"
                "Refusing to run against public IPs.  Use --allow-public AND\n"
                "re-pass --i-am-authorized if you really mean it.",
                target_ip,
            )
            sys.exit(1)
        # Second confirmation
        try:
            answer = input(
                f"\n  WARNING: {target_ip} is a PUBLIC address.\n"
                "  Type 'I am authorized' to confirm you have permission: "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer != "I am authorized":
            LOGGER.error("Authorization not confirmed. Exiting.")
            sys.exit(1)


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------

def cmd_intercept(args: argparse.Namespace) -> None:
    """Handle the ``intercept`` subcommand."""
    from . import interceptor, mitm, rules as rules_mod
    from .tui import LiveDashboard

    print(BANNER)
    print(DISCLAIMER)

    mitm.require_root()
    _check_authorization(args.target, args.allow_public)

    # Load rules
    config_path = Path(args.config)
    ruleset = rules_mod.load_config(config_path)
    LOGGER.info("Loaded %d rules from %s", len(ruleset.rules), config_path)

    # Set up TUI
    dashboard: LiveDashboard | None = None
    if not args.no_tui:
        dashboard = LiveDashboard(use_json_log=args.log_json)
        dashboard.start()

    # JSON logger callback
    json_logger = dashboard.json_log if dashboard else None

    # Build packet handler
    handler = interceptor.PacketHandler(
        ruleset=ruleset,
        dry_run=args.dry_run,
        json_logger=json_logger,
    )

    # Set up MITM (ARP spoof + iptables)
    session = mitm.create_session(
        target_ip=args.target,
        gateway_ip=args.gateway,
        interface=args.interface,
        queue_num=args.queue_num,
        on_cleanup=lambda: dashboard.stop() if dashboard else None,
    )
    session.setup()

    LOGGER.info("Target : %s  Gateway: %s", args.target, session.gateway_ip)
    LOGGER.info("Interface: %s  Queue: %d", session.interface, args.queue_num)
    if args.dry_run:
        LOGGER.info("DRY-RUN mode: no packets will be modified.")

    # Run: NFQUEUE in a background thread, ARP spoof in the main thread
    import threading

    queue_thread = threading.Thread(
        target=interceptor.run_queue,
        args=(args.queue_num, handler),
        daemon=True,
    )
    queue_thread.start()

    try:
        session.spoof_loop()
    except KeyboardInterrupt:
        pass
    finally:
        session.cleanup()
        if dashboard:
            dashboard.stop()

    LOGGER.info(
        "Session complete. Matched: %d  Replaced: %d",
        handler.stats.requests_matched,
        handler.stats.responses_replaced,
    )


def cmd_detect(args: argparse.Namespace) -> None:
    """Handle the ``detect`` subcommand."""
    from . import detector, mitm

    print(BANNER)
    print(DISCLAIMER)

    _check_authorization(args.target if hasattr(args, "target") else None, False)

    def _alert_callback(alert) -> None:
        """Print alerts as they arrive."""
        print(f"\n  [!] {alert.severity.upper()}: {alert.message}")

    monitor = detector.PassiveMonitor(
        gateway_ip=args.gateway,
        interface=args.interface,
        callback=_alert_callback,
    )

    LOGGER.info("Starting passive monitor. Press Ctrl+C to stop.")
    try:
        monitor.start(count=args.count)
    except KeyboardInterrupt:
        pass

    total = len(monitor.all_alerts)
    LOGGER.info("Monitor stopped. Total alerts: %d", total)


def cmd_serve(args: argparse.Namespace) -> None:
    """Handle the ``serve`` subcommand — spin up a lab HTTP server."""
    import functools
    import http.server
    import socketserver

    serve_dir = Path(args.dir).resolve()
    serve_dir.mkdir(parents=True, exist_ok=True)

    # Write the EICAR file if it doesn't exist
    eicar_path = serve_dir / "payloads" / "eicar.com"
    eicar_path.parent.mkdir(parents=True, exist_ok=True)
    if not eicar_path.exists():
        eicar_path.write_text(EICAR_STRING, encoding="ascii")
        LOGGER.info("Wrote EICAR test file to %s", eicar_path)
    else:
        LOGGER.info("EICAR test file already exists at %s", eicar_path)

    handler = functools.partial(http.server.SimpleHTTPRequestHandler,
                                directory=str(serve_dir))

    with socketserver.TCPServer(("0.0.0.0", args.port), handler) as httpd:
        LOGGER.info("Serving %s on port %d (Ctrl+C to stop)...", serve_dir, args.port)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            LOGGER.info("Server stopped.")


def cmd_eicar(args: argparse.Namespace) -> None:
    """Handle the ``eicar`` subcommand."""
    out = Path(args.output)
    out.write_text(EICAR_STRING, encoding="ascii")
    LOGGER.info("EICAR test file written to %s (%d bytes)", out, len(EICAR_STRING))


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def _setup_logging(verbose: bool, json_output: bool) -> None:
    """Configure the root logger."""
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    datefmt = "%H:%M:%S"

    handler: logging.Handler
    if json_output:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(
            '{"time":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}',
            datefmt=datefmt,
        ))
    else:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(fmt, datefmt=datefmt))

    logging.root.setLevel(level)
    logging.root.addHandler(handler)


def main(argv: Sequence[str] | None = None) -> int:
    """Program entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    _setup_logging(args.verbose, getattr(args, "log_json", False))

    commands = {
        "intercept": cmd_intercept,
        "detect": cmd_detect,
        "serve": cmd_serve,
        "eicar": cmd_eicar,
    }

    handler = commands.get(args.command)
    if handler is None:
        parser.print_help()
        return 1

    try:
        handler(args)
    except KeyboardInterrupt:
        print()
        LOGGER.info("Interrupted by user.")
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 1
    except Exception:
        LOGGER.exception("Fatal error")
        return 1

    return 0
