<div align="center">

# 🔍 EvidenceGuardian

**AI-native security research framework that doesn't just *claim* vulnerabilities — it *proves* them with reproducible evidence chains.**

[![Tests](https://img.shields.io/badge/tests-17%20passed-brightgreen)](https://github.com/cy1ingachref/evidence-guardian)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](https://github.com/cy1ingachref/evidence-guardian/blob/main/LICENSE)

*Point it at a web app. It finds potential issues using AI, then autonomously generates working proofs — actual HTTP request/response pairs, PoC scripts, and self-contained evidence bundles.*

**Not "AI says X is vulnerable." More like: *here is the exact sequence that triggers the bug, re-run it yourself.***

[Quick Start](#quick-start) • [Demo](#demo) • [Features](#features) • [Architecture](#architecture) • [Screenshots](#screenshots)

</div>

---

## Why This Exists

Most AI security tools today are "trust me bro" — they hallucinate findings with no proof, or flag things that look suspicious but have no reproducible evidence. Security researchers and bug bounty hunters end up wasting time chasing false positives.

EvidenceGuardian takes a different approach: **every finding must carry verifiable evidence. No proof, no claim.**

---

## Quick Start

```bash
# Install
pip install evidence-guardian

# Set your free LLM key (optional — works in mock mode without one)
export NOUS_API_KEY="your-nous-portal-key"

# Run a scan
evidence-guardian scan https://your-authorized-target.com --scope "Only test /api/* endpoints"

# View the report
evidence-guardian report --open
```

Or try the demo (no API key needed, no external targets):

```bash
evidence-guardian demo
```

---

## Demo

```bash
$ evidence-guardian demo

EvidenceGuardian Demo Mode
This will:
1. Start a local vulnerable Flask app
2. Run a full scan against it
3. Generate an HTML evidence report

No external targets. No API key needed.

  Running ssrf... ---------------------------------------- 100%
  Running idor... ---------------------------------------- 100%
  Running xss...  ---------------------------------------- 100%
  Running sqli... ---------------------------------------- 100%
  Running open_redirect... ---------------------------------------- 100%

============================================================
EvidenceGuardian Scan Report
============================================================
Target: http://127.0.0.1:5000
Duration: 12.7s
Modules: ssrf, idor, xss, sqli, open_redirect
LLM: mock-deterministic

Findings: 5 total, 5 proven

┌─────────────┬──────┬──────────┬───────────────────────────────────┬────────┐
│ ID          │ Type │ Severity │ Endpoint                          │ Proven │
├─────────────┼──────┼──────────┼───────────────────────────────────┼────────┤
│ EG-SSRF-663 │ SSRF │ HIGH     │ http://127.0.0.1:5000/api/fetch   │   ✓    │
│ EG-SSRF-478 │ SSRF │ MEDIUM   │ http://127.0.0.1:5000/api/proxy   │   ✓    │
│ EG-IDOR-607 │ IDOR │ HIGH     │ http://127.0.0.1:5000/api/users/1 │   ✓    │
│ EG-XSS-897  │ XSS  │ MEDIUM   │ http://127.0.0.1:5000/search      │   ✓    │
│ EG-SQLI-299 │ SQLi │ CRITICAL │ http://127.0.0.1:5000/api/login   │   ✓    │
└─────────────┴──────┴──────────┴───────────────────────────────────┴────────┘

Proven Findings (with evidence):

  EG-SSRF-663: Server fetches user-supplied URLs without validation.
    Request: GET http://127.0.0.1:5000/api/fetch?url=http://169.254.169.254/...
    Response: 200
    PoC script available

  EG-IDOR-607: Changing user_id from 1 to 2 returns data belonging to a different user.
    Request: GET http://127.0.0.1:5000/api/users/2
    Response: 200
    PoC script available

  EG-SQLI-299: SQL error triggered by payload in id parameter.
    Request: GET http://127.0.0.1:5000/api/login?id='
    Response: 500
    PoC script available

Report saved to: reports/evidence_guardian_127.0.0.1_5000_20260916.html
```

---

## Features

- **🤖 AI-Powered Analysis** — Uses free LLM (hy3:free via Nous Portal) to identify potential vulnerabilities
- **🔬 Automatic Proof Generation** — For each finding, generates a working PoC (HTTP request/response, script)
- **📋 Reproducible Evidence** — Every finding includes the exact steps to reproduce
- **📊 Self-Contained HTML Reports** — Downloadable evidence bundles with all request/response data embedded
- **🎯 Scope-Aware** — Only targets what you explicitly authorize
- **🛡️ Multi-Vulnerability Coverage** — SSRF, IDOR, XSS, SQLi, Open Redirect
- **💻 Beautiful CLI** — Rich terminal UI with progress indicators and evidence review
- **🧪 Fully Tested** — 17 tests covering all modules, all passing

---

## Vulnerability Modules

| Module | Description | Proof Type | Severity Range |
|--------|-------------|------------|----------------|
| **SSRF** | Server-Side Request Forgery via unvalidated URL parameters | HTTP request/response + internal service detection | MEDIUM — HIGH |
| **IDOR** | Insecure Direct Object Reference via identifier manipulation | Multiple user context comparison | HIGH |
| **XSS** | Reflected Cross-Site Scripting via unencoded input reflection | Payload reflection proof | MEDIUM |
| **SQLi** | SQL Injection via unparameterized queries | Error-based & time-based detection | CRITICAL |
| **Open Redirect** | Unvalidated redirect parameters | Redirect chain capture | MEDIUM |

---

## Architecture

```
evidence_guardian/
├── llm.py          # LLM client (Nous Portal hy3:free, mock fallback)
├── core.py         # Data models: Finding, Evidence, ScanTarget, ScanResult
├── scanner.py      # Orchestrator — runs all modules, collects findings
├── reporter.py     # HTML report generator (self-contained evidence bundles)
├── cli.py          # Click CLI: scan, view, demo, info
└── vulns/
    ├── ssrf.py          # SSRF detection + proof generation
    ├── idor.py          # IDOR detection + proof generation
    ├── xss.py           # XSS detection + proof generation
    ├── sqli.py          # SQLi detection + proof generation
    └── open_redirect.py # Open redirect detection + proof generation
```

### How It Works

1. **Target Definition** — Define an authorized scan target with scope
2. **Module Execution** — Each vulnerability module probes the target
3. **Evidence Capture** — For each finding, capture HTTP request/response pairs
4. **Proof Generation** — Generate a standalone PoC script
5. **LLM Enrichment** — (Optional) Use LLM to add remediation advice and impact analysis
6. **Report Generation** — Package everything into a self-contained HTML evidence bundle

---

## Screenshots

### Terminal Output
```
┌─────────────┬──────┬──────────┬───────────────────────────────────┬────────┐
│ ID          │ Type │ Severity │ Endpoint                          │ Proven │
├─────────────┼──────┼──────────┼───────────────────────────────────┼────────┤
│ EG-SSRF-663 │ SSRF │ HIGH     │ http://127.0.0.1:5000/api/fetch   │   ✓    │
│ EG-IDOR-607 │ IDOR │ HIGH     │ http://127.0.0.1:5000/api/users/1 │   ✓    │
│ EG-SQLI-299 │ SQLi │ CRITICAL │ http://127.0.0.1:5000/api/login   │   ✓    │
└─────────────┴──────┴──────────┴───────────────────────────────────┴────────┘
```

### HTML Report
The generated report is a single HTML file with:
- Dark-themed dashboard with severity statistics
- Each finding with full request/response details
- Embedded PoC scripts (copy-paste runnable)
- Remediation advice and impact analysis
- Evidence fingerprints for integrity verification

---

## Installation

### From PyPI (recommended)
```bash
pip install evidence-guardian
```

### From Source
```bash
git clone https://github.com/cy1ingachref/evidence-guardian.git
cd evidence-guardian
pip install -e ".[dev]"
```

### LLM Configuration (Optional)
EvidenceGuardian works out of the box in **mock mode** (deterministic, no API key needed).

For real AI-powered analysis, set your Nous Portal API key:
```bash
export NOUS_API_KEY="your-key-here"
```

Get a free key at [portal.nousresearch.com](https://portal.nousresearch.com/).

---

## CLI Reference

### `scan` — Run a security scan
```bash
evidence-guardian scan <url> [options]

Options:
  -s, --scope TEXT     Scope description for the scan
  -m, --modules TEXT   Comma-separated modules [default: ssrf,idor,xss,sqli,open_redirect]
  -o, --output TEXT    Output directory [default: reports]
  --mock / --no-mock   Force mock LLM mode
  --open / --no-open   Open HTML report after scan
```

### `demo` — Run the local demo
```bash
evidence-guardian demo
```

### `view` — Open an existing report
```bash
evidence-guardian view <report_path>
```

### `info` — Show configuration
```bash
evidence-guardian info
```

---

## Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all tests
pytest tests/ -v

# Run specific module tests
pytest tests/test_evidence_guardian.py::TestSSRFModule -v
pytest tests/test_evidence_guardian.py::TestIDORModule -v
pytest tests/test_evidence_guardian.py::TestXSSModule -v
pytest tests/test_evidence_guardian.py::TestSQLiModule -v
pytest tests/test_evidence_guardian.py::TestOpenRedirectModule -v
```

---

## Philosophy

1. **Every claim must carry proof** — If we can't show it working, we don't report it
2. **Authorized targets only** — Scope gating built into the core
3. **Reproducible by design** — Evidence bundles are self-contained
4. **No hallucination theater** — False positives are flagged, not hidden
5. **Free to use** — No paid APIs required, works offline in mock mode

---

## Roadmap

- [ ] Add authentication scanning (JWT, session management)
- [ ] Add API endpoint discovery (OpenAPI/Swagger parsing)
- [ ] Add CI/CD integration (GitHub Actions, GitLab CI)
- [ ] Add webhook notifications for findings
- [ ] Add PDF report export
- [ ] Add custom vulnerability module API
- [ ] Add rate limiting and polite scanning mode

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Write tests for your changes
4. Ensure all tests pass (`pytest tests/ -v`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Author

Built by [Achref Ferjani](https://github.com/cy1ingachref) — security researcher, bug bounty hunter, PFE student at ISSATM Bizerte, Tunisia.

---

## Star History

If this project helps you, please ⭐ it on GitHub!

---

<div align="center">

**Every finding must carry proof. No proof, no claim.**

</div>
