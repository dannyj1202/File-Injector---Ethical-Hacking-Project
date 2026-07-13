"""Allow running as ``python -m http_download_interceptor``."""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
