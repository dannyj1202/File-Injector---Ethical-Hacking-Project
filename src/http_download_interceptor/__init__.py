"""HTTP Download Interceptor — an educational MITM demo for authorized lab use.

This tool demonstrates why unencrypted HTTP downloads are vulnerable to
man-in-the-middle tampering. It intercepts plaintext HTTP responses and
transparently rewrites file-download redirects to a harmless EICAR test file
served from a local lab server.

LEGAL / ETHICAL NOTICE:
    This tool is for AUTHORIZED security testing on networks you own or have
    written permission to test. Unauthorized use is illegal.
"""

from __future__ import annotations

__version__ = "1.0.0"
__author__ = "dannyj1202"
