"""Tests for http_download_interceptor.rules — rule matching and config loading."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from http_download_interceptor.rules import (
    Rule,
    Ruleset,
    _built_in_default,
    _normalise_rule,
    _parse_config,
    load_json_config,
    load_yaml_config,
)


# ---------------------------------------------------------------------------
# Rule.matches
# ---------------------------------------------------------------------------

class TestRuleMatches:
    """Unit tests for the Rule.matches() method."""

    def test_extension_match(self):
        rule = Rule(name="exe", replacement_url="http://lab/eicar",
                     extensions=(".exe", ".msi"))
        assert rule.matches("/downloads/setup.exe") is True
        assert rule.matches("/downloads/setup.msi") is True
        assert rule.matches("/downloads/photo.jpg") is False

    def test_extension_case_insensitive(self):
        rule = Rule(name="pdf", replacement_url="http://lab/eicar",
                     extensions=(".pdf",))
        assert rule.matches("/DOC.PDF") is True
        assert rule.matches("/doc.pdf") is True

    def test_host_regex_match(self):
        rule = Rule(name="host", replacement_url="http://lab/eicar",
                     extensions=(".exe",),
                     host_regex=r".*\.example\.com")
        assert rule.matches("/f.exe", host="cdn.example.com") is True
        assert rule.matches("/f.exe", host="evil.com") is False

    def test_path_regex_match(self):
        rule = Rule(name="path", replacement_url="http://lab/eicar",
                     path_regex=r"/downloads/.*")
        assert rule.matches("/downloads/setup.exe") is True
        assert rule.matches("/images/photo.jpg") is False

    def test_content_type_regex_match(self):
        rule = Rule(name="ct", replacement_url="http://lab/eicar",
                     content_type_regex=r"application/octet-stream")
        assert rule.matches("/f.bin", content_type="application/octet-stream") is True
        assert rule.matches("/f.bin", content_type="text/html") is False

    def test_all_filters_combined(self):
        rule = Rule(name="combo", replacement_url="http://lab/eicar",
                     extensions=(".exe",),
                     host_regex=r".*\.example\.com",
                     path_regex=r"/downloads/.*")
        assert rule.matches("/downloads/app.exe", host="cdn.example.com") is True
        assert rule.matches("/downloads/app.exe", host="evil.com") is False
        assert rule.matches("/images/app.exe", host="cdn.example.com") is False

    def test_no_filters_always_matches(self):
        rule = Rule(name="catchall", replacement_url="http://lab/eicar")
        assert rule.matches("/anything/at/all") is True

    def test_empty_extensions_skips_check(self):
        rule = Rule(name="noext", replacement_url="http://lab/eicar",
                     extensions=())
        assert rule.matches("/file.xyz") is True


# ---------------------------------------------------------------------------
# Ruleset.match
# ---------------------------------------------------------------------------

class TestRulesetMatch:
    def test_first_match_wins(self):
        r1 = Rule(name="first", replacement_url="http://a", extensions=(".exe",))
        r2 = Rule(name="second", replacement_url="http://b", extensions=(".exe",))
        rs = Ruleset(rules=(r1, r2))
        assert rs.match("/f.exe") == "http://a"

    def test_fallback_to_default(self):
        rs = Ruleset(
            rules=(Rule(name="exe", replacement_url="http://a", extensions=(".exe",)),),
            default_url="http://default",
        )
        assert rs.match("/f.pdf") == "http://default"

    def test_no_match_no_default(self):
        rs = Ruleset(rules=(Rule(name="exe", replacement_url="http://a", extensions=(".exe",)),))
        assert rs.match("/f.pdf") is None

    def test_empty_ruleset_with_default(self):
        rs = Ruleset(default_url="http://default")
        assert rs.match("/anything") == "http://default"


# ---------------------------------------------------------------------------
# _normalise_rule
# ---------------------------------------------------------------------------

class TestNormaliseRule:
    def test_normalises_extensions(self):
        raw = {"name": "test", "replacement_url": "http://x", "extensions": ["exe", "PDF"]}
        norm = _normalise_rule(raw)
        assert norm["extensions"] == (".exe", ".pdf")

    def test_handles_ext_key(self):
        raw = {"name": "test", "replacement_url": "http://x", "ext": [".zip"]}
        norm = _normalise_rule(raw)
        assert norm["extensions"] == (".zip",)

    def test_strips_empty_regex(self):
        raw = {"name": "test", "replacement_url": "http://x", "host_regex": ""}
        norm = _normalise_rule(raw)
        assert "host_regex" not in norm


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

class TestConfigLoading:
    def test_yaml_load(self, tmp_path):
        cfg = tmp_path / "rules.yaml"
        cfg.write_text(textwrap.dedent("""\
            rules:
              - name: test
                extensions: [".exe"]
                replacement_url: "http://lab/eicar"
            default:
              replacement_url: "http://lab/default"
        """))
        rs = load_yaml_config(cfg)
        assert len(rs.rules) == 1
        assert rs.rules[0].name == "test"
        assert rs.default_url == "http://lab/default"

    def test_json_load(self, tmp_path):
        cfg = tmp_path / "rules.json"
        data = {
            "rules": [
                {"name": "j", "extensions": [".zip"], "replacement_url": "http://j"}
            ],
            "default": {"replacement_url": "http://d"},
        }
        cfg.write_text(json.dumps(data))
        rs = load_json_config(cfg)
        assert len(rs.rules) == 1
        assert rs.default_url == "http://d"

    def test_missing_file_uses_built_in(self, tmp_path):
        rs = load_yaml_config(tmp_path / "nonexistent.yaml")
        assert len(rs.rules) > 0
        assert rs.default_url is not None

    def test_auto_detect_yaml(self, tmp_path):
        cfg = tmp_path / "rules.yml"
        cfg.write_text("rules: []\ndefault: http://d")
        rs = load_yaml_config(cfg)
        assert rs.default_url == "http://d"


# ---------------------------------------------------------------------------
# Built-in default
# ---------------------------------------------------------------------------

class TestBuiltInDefault:
    def test_has_executable_rules(self):
        rs = _built_in_default()
        assert len(rs.rules) >= 1
        assert ".exe" in rs.rules[0].extensions

    def test_has_default_url(self):
        rs = _built_in_default()
        assert rs.default_url is not None
        assert "eicar" in rs.default_url
