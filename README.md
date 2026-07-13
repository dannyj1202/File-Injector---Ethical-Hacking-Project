# HTTP Download Interceptor

> **An educational man-in-the-middle tool that demonstrates why unencrypted HTTP
> downloads are vulnerable to tampering — and why HTTPS exists.**


[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)

---

## What It Does

This tool positions itself as a **man-in-the-middle** on a local network using
ARP spoofing, then watches for plaintext HTTP file downloads. When it detects a
download matching operator-configured rules (by extension, host, path, or
Content-Type), it **transparently rewrites the HTTP 200 OK response into a 301
redirect** pointing at a harmless EICAR antivirus test file hosted on a local
lab server.

**This does NOT auto-execute anything.** The browser simply downloads the
substituted file. The user must still open it. There is no drive-by execution —
that would require a separate browser exploit, which is entirely out of scope.

### Why This Barely Works Anymore

Modern defenses have made this attack largely obsolete on the real internet:

| Defense | How It Stops This |
|---------|-------------------|
| **HTTPS / TLS** | Encrypts the entire connection; MITM cannot read or modify HTTP traffic without certificate forgery |
| **HSTS** | Forces browsers to use HTTPS even if the user types `http://` |
| **Signed Downloads** | OS verifies the download came from the expected publisher |
| **Code Signing** | Executables are signed; replacing them breaks the signature |
| **Subresource Integrity (SRI)** | JS/CSS files are verified by hash; tampering is detected |
| **Content-Type Enforcement** | Browsers enforce declared Content-Type, catching mismatches |

The tool works **only in controlled lab environments** where a victim VM
explicitly uses HTTP to download files over a network the operator owns.

---

## How It Works

```
                          ┌──────────────────────────────────────────────┐
                          │             ATTACKER'S MACHINE               │
                          │                                              │
  ┌──────────┐            │  ┌─────────┐  ┌────────────┐  ┌──────────┐ │
  │  VICTIM  │  ARP       │  │  ARP    │  │  NFQUEUE   │  │  Lab     │ │
  │  (VMM)   │  spoof     │  │  spoof  │  │  packet    │  │  HTTP    │ │
  │          ├────────────┼──┤  (scapy)│  │  handler   │  │  server  │ │
  │  Browser │            │  │         │  │            │  │  (EICAR) │ │
  └────┬─────┘            │  └────┬────┘  └─────┬──────┘  └────┬─────┘ │
       │                  │       │             │              │        │
       │ 1. GET /app.exe  │       │             │              │        │
       ├──────HTTP────────┼──────►│  passes     │              │        │
       │                  │       │  through    │              │        │
       │                  │       │             │              │        │
       │ 2. 200 OK        │       │             │              │        │
       │    (real .exe)   │◄──────┼─────────────┤              │        │
       │                  │       │  intercepted│              │        │
       │                  │       │             │              │        │
       │ 3. Rewritten:    │       │             │   301        │        │
       │    301 → lab/eicar       │             ├──Location──►│        │
       │                  │       │             │              │        │
       │ 4. Browser follows redirect              │            │        │
       │    GET /payloads/eicar.com               │   ────────►│        │
       │                  │       │             │              │        │
       │ 5. 200 OK        │       │             │              │        │
       │    (EICAR file)  │◄──────┼─────────────┼──────────────┤        │
       └──────────────────┘       └─────────────┘              └────────┘
```

### The Theory

1. **HTTP Request/Response**: The victim's browser sends a `GET /downloads/app.exe`
   to a remote server. The response is `200 OK` with the real file body.

2. **TCP ACK/SEQ Correlation**: The interceptor tracks the TCP sequence numbers
   from the outgoing request so it can identify which incoming response belongs to
   which request. This is the `ack_list` concept from the original demo, now
   made robust.

3. **NFQUEUE Interception**: An `iptables` rule sends the victim's packets through
   a Linux NFQUEUE. The Python handler reads each packet, inspects it, and can
   accept, modify, or drop it.

4. **ARP Spoofing**: Scapy sends forged ARP replies to poison the victim's and
   gateway's ARP caches, routing traffic through the attacker.

---

## Features

- **Config-driven rules** — YAML/JSON ruleset maps file extensions, host regex,
  path regex, and Content-Type patterns to replacement URLs.
- **Generic file matching** — works with `.exe`, `.msi`, `.pdf`, `.zip`, `.jpg`,
  `.png`, or any extension you configure.
- **Live TUI dashboard** — real-time terminal display of intercepted downloads
  with colour-coded severity.
- **Defensive companion mode** — passive monitor that detects ARP spoofing and
  download tampering (the blue-team counterpart).
- **Structured JSON logging** — pipe to `jq`, ELK, or any log aggregator.
- **Dry-run mode** — see what *would* happen without modifying any packets.
- **Clean teardown** — automatic ARP cache restoration, iptables cleanup, and IP
  forwarding restoration on Ctrl+C or crash.
- **Authorization gate** — refuses to run unless `--i-am-authorized` is passed
  AND the target is RFC 1918 (with a second confirmation for public IPs).
- **Auto-detection** — interface and gateway are auto-detected with flag overrides.
- **Zero dependencies for pure logic** — rule matching and HTTP rewriting are
  pure functions, fully testable without network access.

---

## Project Structure

```
http-download-interceptor/
├── src/
│   └── http_download_interceptor/
│       ├── __init__.py          # Package metadata
│       ├── __main__.py          # python -m entry point
│       ├── cli.py               # Argument parser + subcommand dispatch
│       ├── interceptor.py       # NFQUEUE packet handler (the engine)
│       ├── http_rewrite.py      # HTTP parsing + 301 redirect builder
│       ├── rules.py             # Config-driven rule engine
│       ├── mitm.py              # ARP spoof + iptables + IP forwarding
│       ├── tui.py               # Live terminal dashboard
│       └── detector.py          # Defensive passive monitor
├── tests/
│   ├── conftest.py              # Shared fixtures, Scapy mock
│   ├── test_rules.py            # Rule matching + config loading
│   ├── test_http_rewrite.py     # HTTP parsing + redirect building
│   └── test_interceptor.py      # Packet handler + tracker logic
├── config/
│   └── rules.yaml               # Sample rule configuration
├── .github/workflows/
│   └── ci.yml                   # GitHub Actions: ruff + flake8 + pytest
├── pyproject.toml               # Package metadata + tool config
├── requirements.txt             # Runtime dependencies
├── requirements-dev.txt         # Dev/test dependencies
├── LICENSE                      # MIT
├── CONTRIBUTING.md              # Contribution guidelines
└── README.md                    # You are here
```

---

## Lab Setup

### Prerequisites

- **Attacker VM**: Kali Linux (or any Linux with Python 3.10+, Scapy, iptables)
- **Victim VM**: Any OS with a web browser (Windows, Linux, macOS)
- **Lab HTTP Server**: A simple Python HTTP server serving the EICAR test file
- All VMs on the same virtual network (e.g., VirtualBox Host-Only)

### Network Topology

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Victim    │     │   Attacker  │     │  Lab Server │
│ 192.168.1.10│     │ 192.168.1.5 │     │ 192.168.1.5 │
│             │     │             │     │  :8000      │
│  Browser    │◄────┤  ARP spoof  │     │  eicar.com  │
│  (HTTP)     │     │  NFQUEUE    │◄────┤             │
└─────────────┘     │  intercept  │     └─────────────┘
                    └─────────────┘
```

### Step-by-Step

```bash
# 1. On the lab server (or attacker itself), start the HTTP file server:
sudo http-download-interceptor serve --port 8000 --i-am-authorized
# This writes eicar.com to ./payloads/ and serves it on port 8000.

# 2. Edit the rules to match your lab IP:
#    config/rules.yaml → change 192.168.1.100 to your lab server IP

# 3. On the attacker, start the interceptor:
sudo http-download-interceptor intercept \
    -t 192.168.1.10 \
    -g 192.168.1.1 \
    -c config/rules.yaml \
    --i-am-authorized

# 4. On the victim, open a browser and download a .exe file over HTTP.
#    The browser will receive a 301 redirect → downloads the EICAR file.

# 5. Ctrl+C on the attacker to stop. ARP caches are auto-restored.
```

### Sample Output

```
22:41:03 [INFO] Loaded 6 rules from config/rules.yaml
22:41:03 [INFO] Target : 192.168.1.10  Gateway: 192.168.1.1
22:41:03 [INFO] NFQUEUE 0 bound. Waiting for packets...
22:41:15 [INFO] [MATCH] GET example.com /downloads/eicar.com
                 -> http://192.168.1.5:8000/payloads/eicar.com
22:41:15 [INFO] [REPLACE] /downloads/eicar.com -> 301 -> http://192.168.1.5:8000/payloads/eicar.com
```

---

## Installation

```bash
git clone https://github.com/dannyj1202/http-download-interceptor.git
cd http-download-interceptor
pip install -e ".[dev]"
```

**System requirements**: Linux with `iptables` (for NFQUEUE). macOS can run
the rule engine and tests, but not the live interceptor.

### Requirements

- Python 3.10+
- `scapy` — packet crafting and ARP spoofing
- `NetfilterQueue` — Linux NFQUEUE bindings
- `PyYAML` — YAML config parsing

---

## Usage

```bash
# Start the interceptor (requires root + authorization)
sudo http-download-interceptor intercept \
    -t 192.168.1.10 \
    --i-am-authorized

# Dry-run mode — log matches without modifying packets
sudo http-download-interceptor intercept \
    -t 192.168.1.10 \
    --dry-run \
    --i-am-authorized

# Run the defensive passive monitor
sudo http-download-interceptor detect \
    --i-am-authorized

# Start the lab HTTP server
http-download-interceptor serve --port 8000 --i-am-authorized

# Write the EICAR test file to disk
http-download-interceptor eicar

# All commands support -v for verbose logging and --log-json for
# structured JSON output to stderr.
```

---

## Defenses & Detection

Understanding how to **stop** this attack is more important than executing it.

### Why HTTPS Defeats This Entirely

TLS encrypts the HTTP request *and* response. The MITM cannot:
- Read the URL path or Host header
- See the Content-Type header
- Modify the response body or status code
- Inject a 301 redirect

Even a passive MITM (who can see traffic but not modify it) gets only
encrypted ciphertext.

### Content-Type Mismatch Detection

When this tool redirects a `.exe` download to an EICAR file, the browser receives
a body that doesn't match the expected Content-Type. Modern defences include:

- **Content sniffing protections** (X-Content-Type-Options: nosniff)
- **Subresource Integrity (SRI)** — verifies file hashes
- **Code signing** — OS checks the publisher's signature
- **Browser download warnings** — Chrome/Firefox flag suspicious redirects

### ARP Spoof Detection

The defensive companion mode (`detect` subcommand) watches for:
- Multiple MAC addresses replying for the same IP
- Gateway MAC address changes
- Gratuitous ARP replies
- HTTP 3xx redirects on file downloads

### Network-Level Defences

- **Dynamic ARP Inspection (DAI)** on managed switches
- **ARP spoofing detection** in enterprise firewalls
- **Network segmentation** — isolate sensitive VLANs
- **802.1X port authentication** — only authorized devices on the network
- **VPN / WireGuard** — encrypt all traffic, MITM becomes irrelevant

---

## Ethics & Legal Disclaimer

**This tool is for AUTHORIZED SECURITY TESTING ONLY.**

- You must own the network or have **explicit written authorization** to test it.
- Running this against networks you don't own is **illegal** in most jurisdictions
  (Computer Fraud and Abuse Act, Computer Misuse Act, etc.).
- The tool **refuses to run** without the `--i-am-authorized` flag and checks
  that the target is in an RFC 1918 private range.
- The only "payload" is the **EICAR antivirus test file** — a harmless string
  that every major AV vendor flags as a test. No real malware is used, created,
  or generated.
- The tool **auto-restores** the network (ARP caches, iptables, IP forwarding)
  on exit, so the network is always left clean.

**You are solely responsible for how you use this tool.**

---

## Skills Demonstrated

| Skill | Where |
|-------|-------|
| Python packaging & CLI design | `pyproject.toml`, `cli.py`, `__main__.py` |
| Scapy packet manipulation | `mitm.py`, `interceptor.py` |
| Linux iptables / NFQUEUE | `interceptor.py`, `mitm.py` |
| ARP protocol & cache poisoning | `mitm.py` (reuses `arp_spoofer` project) |
| HTTP protocol parsing | `http_rewrite.py` |
| Config-driven rule engine | `rules.py` (YAML/JSON, regex, extension matching) |
| Defensive security / detection | `detector.py` (ARP + download tamper detection) |
| Live TUI / UX design | `tui.py` (ANSI dashboard) |
| Unit testing & mocking | `tests/` (Scapy mocked, pure logic tested) |
| CI/CD | `.github/workflows/ci.yml` (ruff + pytest) |
| Type hints & docstrings | All modules |
| Clean resource management | Signal handlers, try/finally, auto-restore |

---

## Demo GIF

> **Coming soon** — a screen recording showing the attacker starting the
> interceptor, the victim downloading a `.exe` over HTTP, and the EICAR file
> arriving in its place.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Quick start for contributors
git clone https://github.com/dannyj1202/http-download-interceptor.git
cd http-download-interceptor
python -m venv venv && source venv/bin/activate
pip install -e ".[dev]"
ruff check src/ tests/
pytest -v
```

---

## License

[MIT](LICENSE) — see the LICENSE file for full text.

---

## Acknowledgements

- Built during the **PARAMOUNT Internship** — Python Programming + Ethical Hacking track.
- EICAR test file: [eicar.org](https://www.eicar.org/download-anti-malware-testfile/)
- ARP spoofing logic evolved from the [ARP-Spoofer](https://github.com/dannyj1202/ARP-Spoofer) project.
