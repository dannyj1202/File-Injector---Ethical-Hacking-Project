"""Parse and rewrite HTTP responses for download interception.

This module handles the low-level work of:

1. Detecting whether a TCP payload is an HTTP response (status line + headers).
2. Extracting the ``Host`` header, URL path, and ``Content-Type``.
3. Building a synthetic 301 redirect response that points at the replacement URL.

All functions are pure / stateless — they take data in and return data out —
making them easy to unit-test without any network traffic.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

LOGGER = logging.getLogger(__name__)

# Maximum bytes we'll scan for an HTTP header boundary.
_MAX_HEADER_SCAN: int = 8192


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HttpRequestInfo:
    """Parsed metadata extracted from an outgoing HTTP request."""

    method: str
    path: str
    host: str
    headers: dict[str, str]


@dataclass(frozen=True)
class HttpResponseInfo:
    """Parsed metadata from an incoming HTTP response."""

    version: str
    status_code: int
    reason: str
    headers: dict[str, str]
    content_type: str | None = None


@dataclass(frozen=True)
class RewriteResult:
    """The output of a rewrite operation."""

    should_redirect: bool
    redirect_url: str | None = None
    original_path: str | None = None
    matched_by: str | None = None


# ---------------------------------------------------------------------------
# HTTP detection & parsing
# ---------------------------------------------------------------------------

def is_http_request(payload: bytes) -> bool:
    """Return True if *payload* looks like a plaintext HTTP request."""
    if not payload:
        return False
    # HTTP requests start with a method token followed by a space.
    methods = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ")
    return any(payload.startswith(m) for m in methods)


def is_http_response(payload: bytes) -> bool:
    """Return True if *payload* looks like a plaintext HTTP response."""
    if not payload:
        return False
    # HTTP/1.x responses start with "HTTP/1."
    return payload[:7] == b"HTTP/1."


def parse_request_headers(payload: bytes) -> HttpRequestInfo | None:
    """Parse an HTTP request's first line and headers.

    Returns ``None`` if the payload can't be parsed.
    """
    try:
        text = payload[:_MAX_HEADER_SCAN].decode("ascii", errors="replace")
    except Exception:  # noqa: BLE001
        return None

    lines = text.split("\r\n")
    if len(lines) < 2:
        return None

    # Request line: METHOD SP path SP HTTP/x.x
    request_line = lines[0]
    parts = request_line.split(" ", 2)
    if len(parts) < 3:
        return None

    method, path = parts[0], parts[1]

    # Headers
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            break
        if ":" in line:
            key, val = line.split(":", 1)
            headers[key.strip()] = val.strip()

    host = headers.get("Host", "")
    if not host:
        return None

    return HttpRequestInfo(method=method, path=path, host=host, headers=headers)


def parse_response_headers(payload: bytes) -> HttpResponseInfo | None:
    """Parse an HTTP response's first line and headers.

    Returns ``None`` if the payload can't be parsed.
    """
    try:
        text = payload[:_MAX_HEADER_SCAN].decode("ascii", errors="replace")
    except Exception:  # noqa: BLE001
        return None

    lines = text.split("\r\n")
    if len(lines) < 1:
        return None

    # Status line: HTTP/x.x SP code SP reason
    status_line = lines[0]
    parts = status_line.split(" ", 2)
    if len(parts) < 2:
        return None

    version = parts[0]
    try:
        status_code = int(parts[1])
    except ValueError:
        return None
    reason = parts[2] if len(parts) >= 3 else ""

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            break
        if ":" in line:
            key, val = line.split(":", 1)
            headers[key.strip()] = val.strip()

    content_type = headers.get("Content-Type") or headers.get("content-type")

    return HttpResponseInfo(
        version=version,
        status_code=status_code,
        reason=reason,
        headers=headers,
        content_type=content_type,
    )


# ---------------------------------------------------------------------------
# Redirect builder
# ---------------------------------------------------------------------------

def build_301_redirect(
    redirect_url: str,
    original_host: str,
    http_version: str = "HTTP/1.1",
) -> bytes:
    """Build a raw HTTP 301 redirect response packet.

    This is what we inject into the TCP stream in place of the real response.
    """
    body = (
        f"<html><body><h1>301 Moved Permanently</h1>"
        f"<p>The resource has been moved to <a href=\"{redirect_url}\">"
        f"{redirect_url}</a>.</p></body></html>"
    )
    response = (
        f"{http_version} 301 Moved Permanently\r\n"
        f"Host: {original_host}\r\n"
        f"Location: {redirect_url}\r\n"
        f"Content-Type: text/html\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"{body}"
    )
    return response.encode("ascii", errors="replace")


def build_eicar_redirect(
    lab_ip: str,
    lab_port: int = 80,
    path: str = "/payloads/eicar.com",
    original_host: str = "",
    http_version: str = "HTTP/1.1",
) -> bytes:
    """Convenience: build a 301 redirect pointing at the EICAR test file."""
    url = f"http://{lab_ip}:{lab_port}{path}"
    return build_301_redirect(url, original_host, http_version)


# ---------------------------------------------------------------------------
# High-level helpers
# ---------------------------------------------------------------------------

def extract_request_path(payload: bytes) -> str | None:
    """Quickly pull the request path (e.g. ``/downloads/setup.exe``) from a payload."""
    info = parse_request_headers(payload)
    return info.path if info else None


def extract_host(payload: bytes) -> str | None:
    """Quickly pull the ``Host`` header value from a request payload."""
    info = parse_request_headers(payload)
    return info.host if info else None


def correlation_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> tuple:
    """Build a hashable key for request-response correlation.

    We track ``(src_ip, src_port, dst_ip, dst_port)`` on the request side and
    match it against the reversed tuple on the response side.
    """
    return (src_ip, src_port, dst_ip, dst_port)


def response_matches_request(
    resp_src_ip: str,
    resp_src_port: int,
    resp_dst_ip: str,
    resp_dst_port: int,
    request_key: tuple,
) -> bool:
    """Check whether a response packet corresponds to a tracked request.

    The response's src is the server (which was the request's dst) and the
    response's dst is the client (which was the request's src). We reverse
    the response addresses to reconstruct the original request key.
    """
    reverse_key = (resp_dst_ip, resp_dst_port, resp_src_ip, resp_src_port)
    return reverse_key == request_key
