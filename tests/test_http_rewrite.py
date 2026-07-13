"""Tests for http_download_interceptor.http_rewrite — HTTP parsing and rewriting."""

from __future__ import annotations

import pytest

from http_download_interceptor.http_rewrite import (
    HttpRequestInfo,
    HttpResponseInfo,
    build_301_redirect,
    correlation_key,
    extract_host,
    extract_request_path,
    is_http_request,
    is_http_response,
    parse_request_headers,
    parse_response_headers,
    response_matches_request,
)


# ---------------------------------------------------------------------------
# is_http_request / is_http_response
# ---------------------------------------------------------------------------

class TestHttpDetection:
    def test_valid_request(self):
        assert is_http_request(b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n") is True

    def test_post_request(self):
        assert is_http_request(b"POST /api HTTP/1.1\r\nHost: x\r\n\r\n") is True

    def test_empty_not_request(self):
        assert is_http_request(b"") is False

    def test_non_http_not_request(self):
        assert is_http_request(b"\x16\x03\x03") is False  # TLS handshake

    def test_valid_response(self):
        assert is_http_response(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n") is True

    def test_empty_not_response(self):
        assert is_http_response(b"") is False

    def test_non_http_not_response(self):
        assert is_http_response(b"GET / HTTP/1.1\r\n") is False


# ---------------------------------------------------------------------------
# parse_request_headers
# ---------------------------------------------------------------------------

class TestParseRequestHeaders:
    def test_parses_simple_get(self):
        raw = b"GET /downloads/setup.exe HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"
        info = parse_request_headers(raw)
        assert info is not None
        assert info.method == "GET"
        assert info.path == "/downloads/setup.exe"
        assert info.host == "example.com"
        assert info.headers["Accept"] == "*/*"

    def test_returns_none_for_garbage(self):
        assert parse_request_headers(b"not http at all") is None

    def test_returns_none_for_empty(self):
        assert parse_request_headers(b"") is None

    def test_handles_missing_host(self):
        raw = b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n"
        info = parse_request_headers(raw)
        assert info is None  # no Host header

    def test_post_with_content_type(self):
        raw = (
            b"POST /upload HTTP/1.1\r\n"
            b"Host: api.example.com\r\n"
            b"Content-Type: application/json\r\n"
            b"\r\n"
        )
        info = parse_request_headers(raw)
        assert info is not None
        assert info.method == "POST"
        assert info.headers["Content-Type"] == "application/json"


# ---------------------------------------------------------------------------
# parse_response_headers
# ---------------------------------------------------------------------------

class TestParseResponseHeaders:
    def test_parses_200_ok(self):
        raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 100\r\n\r\n"
        info = parse_response_headers(raw)
        assert info is not None
        assert info.status_code == 200
        assert info.reason == "OK"
        assert info.content_type == "text/html"

    def test_parses_301_redirect(self):
        raw = (
            b"HTTP/1.1 301 Moved Permanently\r\n"
            b"Location: http://evil.com/malware.exe\r\n"
            b"\r\n"
        )
        info = parse_response_headers(raw)
        assert info is not None
        assert info.status_code == 301

    def test_returns_none_for_garbage(self):
        assert parse_response_headers(b"not http") is None

    def test_returns_none_for_empty(self):
        assert parse_response_headers(b"") is None


# ---------------------------------------------------------------------------
# build_301_redirect
# ---------------------------------------------------------------------------

class TestBuildRedirect:
    def test_contains_url(self):
        raw = build_301_redirect("http://lab/eicar.com", "example.com")
        assert b"http://lab/eicar.com" in raw
        assert b"301 Moved Permanently" in raw
        assert b"Location: http://lab/eicar.com" in raw

    def test_contains_host(self):
        raw = build_301_redirect("http://lab/eicar.com", "example.com")
        assert b"Host: example.com" in raw

    def test_valid_http_response_format(self):
        raw = build_301_redirect("http://lab/eicar.com", "example.com")
        lines = raw.split(b"\r\n")
        # First line should be "HTTP/1.1 301 Moved Permanently"
        assert lines[0] == b"HTTP/1.1 301 Moved Permanently"

    def test_custom_http_version(self):
        raw = build_301_redirect("http://lab/eicar.com", "x", http_version="HTTP/1.0")
        assert raw.startswith(b"HTTP/1.0 301")


# ---------------------------------------------------------------------------
# Correlation helpers
# ---------------------------------------------------------------------------

class TestCorrelation:
    def test_key_is_tuple(self):
        key = correlation_key("1.2.3.4", 12345, "5.6.7.8", 80)
        assert key == ("1.2.3.4", 12345, "5.6.7.8", 80)

    def test_response_matches_request(self):
        # Request: client(10.0.0.1:44444) -> server(10.0.0.2:80)
        req_key = correlation_key("10.0.0.1", 44444, "10.0.0.2", 80)
        # Response: server(10.0.0.2:80) -> client(10.0.0.1:44444)
        # Function reverses resp src/dst to reconstruct the request key
        assert response_matches_request(
            "10.0.0.2", 80, "10.0.0.1", 44444, req_key
        ) is True

    def test_response_no_match(self):
        req_key = correlation_key("10.0.0.1", 44444, "10.0.0.2", 80)
        assert response_matches_request(
            "10.0.0.3", 80, "10.0.0.1", 44444, req_key
        ) is False


# ---------------------------------------------------------------------------
# Quick helpers
# ---------------------------------------------------------------------------

class TestQuickHelpers:
    def test_extract_path(self):
        raw = b"GET /downloads/app.exe HTTP/1.1\r\nHost: x\r\n\r\n"
        assert extract_request_path(raw) == "/downloads/app.exe"

    def test_extract_host(self):
        raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        assert extract_host(raw) == "example.com"

    def test_extract_path_none(self):
        assert extract_request_path(b"garbage") is None

    def test_extract_host_none(self):
        assert extract_host(b"garbage") is None
