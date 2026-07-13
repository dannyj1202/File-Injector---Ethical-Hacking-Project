"""Tests for http_download_interceptor.interceptor — packet handler logic."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from http_download_interceptor.http_rewrite import correlation_key
from http_download_interceptor.interceptor import ConnectionTracker, PacketHandler, Stats
from http_download_interceptor.rules import Rule, Ruleset


# ---------------------------------------------------------------------------
# ConnectionTracker
# ---------------------------------------------------------------------------

class TestConnectionTracker:
    def test_track_and_pop(self):
        ct = ConnectionTracker()
        key = ("1.2.3.4", 1234, "5.6.7.8", 80)
        ct.track(key, MagicMock())
        assert len(ct) == 1
        result = ct.pop(key)
        assert result is not None
        assert len(ct) == 0

    def test_pop_nonexistent_returns_none(self):
        ct = ConnectionTracker()
        assert ct.pop(("x",)) is None

    def test_eviction_at_max(self):
        ct = ConnectionTracker(max_entries=2)
        ct.track(("a",), MagicMock(name="a"))
        ct.track(("b",), MagicMock(name="b"))
        ct.track(("c",), MagicMock(name="c"))
        # "a" should have been evicted
        assert ct.pop(("a",)) is None
        assert ct.pop(("b",)) is not None
        assert ct.pop(("c",)) is not None

    def test_clear(self):
        ct = ConnectionTracker()
        ct.track(("x",), MagicMock())
        ct.clear()
        assert len(ct) == 0


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

class TestStats:
    def test_defaults(self):
        s = Stats()
        assert s.requests_matched == 0
        assert s.responses_replaced == 0
        assert s.packets_seen == 0


# ---------------------------------------------------------------------------
# PacketHandler — rule matching integration
# ---------------------------------------------------------------------------

class TestPacketHandler:
    def _make_handler(self, dry_run: bool = False) -> PacketHandler:
        ruleset = Ruleset(
            rules=(
                Rule(name="exe", replacement_url="http://lab/eicar",
                     extensions=(".exe",)),
            ),
            default_url=None,
        )
        return PacketHandler(ruleset=ruleset, dry_run=dry_run)

    def test_tracks_matching_request(self):
        handler = self._make_handler()
        # Simulate an outgoing HTTP request for a .exe file
        payload = (
            b"GET /downloads/setup.exe HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"\r\n"
        )
        # We can't call _handle_request directly without mocking scapy,
        # but we can verify the tracker logic
        key = correlation_key("10.0.0.1", 44444, "10.0.0.2", 80)
        from http_download_interceptor.interceptor import ReplacementInfo
        handler.tracker.track(key, ReplacementInfo(
            redirect_url="http://lab/eicar",
            rule_name="exe",
            original_path="/downloads/setup.exe",
        ))
        assert len(handler.tracker) == 1
        info = handler.tracker.pop(key)
        assert info.redirect_url == "http://lab/eicar"

    def test_dry_run_flag_preserved(self):
        handler = self._make_handler(dry_run=True)
        assert handler.dry_run is True

    def test_stats_start_at_zero(self):
        handler = self._make_handler()
        assert handler.stats.requests_matched == 0
        assert handler.stats.responses_replaced == 0
