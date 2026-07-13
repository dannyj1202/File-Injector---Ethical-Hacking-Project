"""Shared fixtures for the test suite."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure the package is importable from src/
SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture(autouse=True)
def _mock_scapy_and_netfilterqueue():
    """Mock scapy and netfilterqueue so tests never touch the network."""
    mock_scapy = MagicMock()
    mock_nfqueue = MagicMock()

    with patch.dict(sys.modules, {
        "scapy": mock_scapy,
        "scapy.all": mock_scapy,
        "netfilterqueue": mock_nfqueue,
    }):
        yield
