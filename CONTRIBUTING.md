# Contributing to HTTP Download Interceptor

Thank you for your interest in contributing! This is an educational security
tool, and we welcome improvements that keep it safe, accurate, and useful.

## Guidelines

### Ethical Use First

- All contributions must maintain the project's **lab-only, educational** focus.
- Never add functionality that enables real-world attacks, malware delivery, or
  AV evasion.
- The only "payload" is the EICAR test file. This is non-negotiable.

### Development Setup

```bash
git clone https://github.com/dannyj1202/http-download-interceptor.git
cd http-download-interceptor
python -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
```

### Code Quality

- Run the linter: `ruff check src/ tests/`
- Run tests: `pytest -v`
- Run type checker: `mypy src/`
- All PRs must pass CI (ruff + pytest) before merge.

### Pull Requests

1. Fork the repo and create a feature branch (`git checkout -b feature/my-change`).
2. Write tests for any new logic.
3. Update the README if you add user-facing features.
4. Keep commits focused and messages clear.

### Reporting Issues

Open a GitHub issue with:
- Steps to reproduce
- Expected vs. actual behaviour
- Python version and OS

## Code of Conduct

Be respectful, constructive, and inclusive. This is an educational project —
help others learn.
