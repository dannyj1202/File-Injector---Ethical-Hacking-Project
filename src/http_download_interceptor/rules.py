"""Config-driven rule engine for matching and replacing HTTP downloads.

Rules are loaded from a YAML (or JSON) file. Each rule maps a file-extension
pattern and/or host/path regex to a replacement URL. The first matching rule
wins; a configurable default rule catches everything else.

Example rules.yaml
------------------
.. code-block:: yaml

    rules:
      - name: executables
        extensions: [".exe", ".msi", ".bat", ".cmd", ".ps1"]
        replacement_url: "http://192.168.1.100/payloads/eicar.com"
      - name: documents
        extensions: [".pdf", ".docx", ".xlsx"]
        host_regex: ".*\\.example\\.com"
        replacement_url: "http://192.168.1.100/payloads/eicar.com"
      - name: images
        extensions: [".jpg", ".png", ".gif"]
        replacement_url: "http://192.168.1.100/payloads/lab-image.bin"

    default:
      replacement_url: "http://192.168.1.100/payloads/eicar.com"
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Rule:
    """A single interception rule."""

    name: str
    replacement_url: str
    extensions: tuple[str, ...] = ()
    host_regex: str | None = None
    path_regex: str | None = None
    content_type_regex: str | None = None

    # Compiled regex caches (built on first use)
    _host_re: re.Pattern[str] | None = field(default=None, repr=False)
    _path_re: re.Pattern[str] | None = field(default=None, repr=False)
    _ct_re: re.Pattern[str] | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Compile regex patterns lazily."""
        if self.host_regex is not None and self._host_re is None:
            object.__setattr__(self, "_host_re", re.compile(self.host_regex, re.I))
        if self.path_regex is not None and self._path_re is None:
            object.__setattr__(self, "_path_re", re.compile(self.path_regex))
        if self.content_type_regex is not None and self._ct_re is None:
            object.__setattr__(self, "_ct_re", re.compile(self.content_type_regex, re.I))

    # ------------------------------------------------------------------
    def matches(
        self,
        url_path: str,
        host: str | None = None,
        content_type: str | None = None,
    ) -> bool:
        """Return True if this rule matches the given request attributes.

        A rule matches when ALL of the following are true:
        * The URL path ends with one of the rule's extensions (if any).
        * The host matches ``host_regex`` (if set).
        * The path matches ``path_regex`` (if set).
        * The Content-Type matches ``content_type_regex`` (if set).
        """
        # Extension check
        if self.extensions:
            lower_path = url_path.lower()
            if not any(lower_path.endswith(ext) for ext in self.extensions):
                return False

        # Host regex
        if self._host_re is not None:
            if host is None or not self._host_re.search(host):
                return False

        # Path regex
        if self._path_re is not None:
            if not self._path_re.search(url_path):
                return False

        # Content-Type regex
        if self._ct_re is not None:
            if content_type is None or not self._ct_re.search(content_type):
                return False

        return True


@dataclass(frozen=True)
class Ruleset:
    """An ordered collection of rules with a default fallback."""

    rules: tuple[Rule, ...] = ()
    default_url: str | None = None

    def match(self, url_path: str, host: str | None = None,
              content_type: str | None = None) -> str | None:
        """Return the replacement URL for the first matching rule, or the default.

        Returns ``None`` when nothing matches and no default is configured
        (meaning the download should pass through untouched).
        """
        for rule in self.rules:
            if rule.matches(url_path, host, content_type):
                LOGGER.debug("Rule '%s' matched %s", rule.name, url_path)
                return rule.replacement_url
        if self.default_url is not None:
            LOGGER.debug("No rule matched; using default for %s", url_path)
            return self.default_url
        return None


# ---------------------------------------------------------------------------
# Config loaders
# ---------------------------------------------------------------------------

def _normalise_rule(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalise a raw dict from YAML/JSON into Rule-compatible keys."""
    normalised: dict[str, Any] = {
        "name": raw.get("name", "unnamed"),
        "replacement_url": raw["replacement_url"],
    }
    # extensions -> tuple of lowercase strings with leading dot
    raw_exts = raw.get("extensions") or raw.get("ext") or []
    exts: list[str] = []
    for e in raw_exts:
        e = str(e).lower()
        if not e.startswith("."):
            e = "." + e
        exts.append(e)
    normalised["extensions"] = tuple(exts)

    for key in ("host_regex", "path_regex", "content_type_regex"):
        if key in raw and raw[key]:
            normalised[key] = raw[key]
    return normalised


def load_yaml_config(path: Path) -> Ruleset:
    """Load a ruleset from a YAML file.

    Falls back to a minimal built-in default if the file is missing.
    Requires ``pyyaml`` (listed in ``requirements.txt``).
    """
    try:
        import yaml  # noqa: WPS433 — conditional import
    except ImportError:
        raise SystemExit(
            "PyYAML is required for YAML config.  Install it with:\n"
            "  pip install pyyaml"
        )

    if not path.exists():
        LOGGER.warning("Config file %s not found — using built-in default.", path)
        return _built_in_default()

    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    return _parse_config(data)


def load_json_config(path: Path) -> Ruleset:
    """Load a ruleset from a JSON file."""
    if not path.exists():
        LOGGER.warning("Config file %s not found — using built-in default.", path)
        return _built_in_default()

    with path.open(encoding="utf-8") as fh:
        data = json.load(fh)

    return _parse_config(data)


def load_config(path: Path) -> Ruleset:
    """Auto-detect format from file extension and load the ruleset."""
    suffix = path.suffix.lower()
    if suffix in (".yaml", ".yml"):
        return load_yaml_config(path)
    if suffix == ".json":
        return load_json_config(path)
    # Default to YAML
    return load_yaml_config(path)


def _parse_config(data: dict[str, Any]) -> Ruleset:
    """Parse a raw config dict into a Ruleset."""
    rules: list[Rule] = []
    for raw_rule in data.get("rules", []):
        normalised = _normalise_rule(raw_rule)
        rules.append(Rule(**normalised))

    default_url: str | None = None
    default_block = data.get("default")
    if isinstance(default_block, dict):
        default_url = default_block.get("replacement_url")
    elif isinstance(default_block, str):
        default_url = default_block

    return Ruleset(rules=tuple(rules), default_url=default_url)


def _built_in_default() -> Ruleset:
    """Fallback ruleset: redirect common executable extensions to EICAR."""
    return Ruleset(
        rules=(
            Rule(
                name="executables",
                replacement_url="http://192.168.1.100/payloads/eicar.com",
                extensions=(".exe", ".msi", ".bat", ".cmd", ".ps1", ".com", ".scr"),
            ),
        ),
        default_url="http://192.168.1.100/payloads/eicar.com",
    )
