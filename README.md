<div align="center">

# EvidenceGuardian

**AI-native security research framework that doesn't just *claim* vulnerabilities — it *proves* them with reproducible evidence chains.**

[![Tests](https://img.shields.io/badge/tests-17%20passed-brightgreen)](https://github.com/cy1ingachref/evidence-guardian)
[![CI](https://github.com/cy1ingachref/evidence-guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/cy1ingachref/evidence-guardian/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](https://github.com/cy1ingachref/evidence-guardian/blob/main/LICENSE)
[![OmniRoute](https://img.shields.io/badge/AI-9%20free%20providers-ff69b4)](https://github.com/cy1ingachref/evidence-guardian)

*Point it at a web app. It finds vulnerabilities using AI, then autonomously generates working proofs — actual HTTP request/response pairs, PoC scripts, and self-contained evidence bundles.*

**Not "AI says X is vulnerable." More like: *here is the exact sequence that triggers the bug, re-run it yourself.***

[Quick Start](#quick-start) • [Demo](#demo) • [OmniRoute](#omniRoute) • [Modules](#modules) • [CLI](#cli-reference) • [Architecture](#architecture)

</div>

---

## Why This Exists

Most AI security tools today are "trust me bro" — they hallucinate findings with no proof, or flag things that look suspicious but have no reproducible evidence. Security researchers and bug bounty hunters waste hours chasing false positives.

EvidenceGuardian takes a different approach: **every finding must carry verifiable evidence. No proof, no claim.**

---

## Quick Start

```bash
# Install
pip install evidence-guardian

# Run with free AI (OmniRoute — auto-detects available providers)
evidence-guardian scan https://your-target.com --omni

# Or run in mock mode (no API key needed, deterministic)
evidence-guardian scan https://your-target.com --mock

# View the report
evidence-guardian view reports/evidence_guardian_*.html
```

Try the demo (no API key, no external targets):

```bash
evidence-guardian demo
```

---

## OmniRoute — Free AI Provider Router

EvidenceGuardian's OmniRoute routes LLM requests across **9 free AI providers** with automatic failover. No paid APIs required.

| Provider | Free Models | Setup |
|----------|-------------|-------|
| **Ollama** | llama3.3, codellama, mistral, gemma2 | Local, no key |
| **Groq** | llama-3.3-70b, llama-3.1-8b, mixtral, gemma2 | `GROQ_API_KEY` |
| **Nous Portal** | hy3:free | `NOUS_API_KEY` |
| **Together AI** | llama-3.3-70b-turbo, mixtral, qwen | `TOGETHER_API_KEY` |
| **OpenRouter** | 20+ free models (llama, mistral, qwen, gemma, phi, deepseek) | `OPENROUTER_API_KEY` |
| **Fireworks** | llama-v3p1-70b, mixtral, qwen | `FIREWORKS_API_KEY` |
| **Mistral** | mistral-small, mistral-medium | `MISTRAL_API_KEY` |
| **DeepInfra** | llama-3.3-70b | `DEEPINFRA_API_KEY` |
| **HuggingFace** | llama-3.3-70b, mistral-7b, qwen, gemma | `HF_API_KEY` |

### Usage

```bash
# Auto-detect and route across available providers
evidence-guardian scan https://target.com --omni

# Prefer a specific provider
evidence-guardian scan https://target.com --omni --provider groq

# Use a specific model
evidence-guardian scan https://target.com --omni --provider groq --model llama-3.1-8b-instant

# Check available providers
evidence-guardian omni

# See free models for a provider
evidence-guardian omni openrouter
```

Get free keys at: [Groq](https://console.groq.com/keys) • [Nous](https://portal.nousresearch.com) • [Together](https://api.together.xyz/settings/api-keys) • [OpenRouter](https://openrouter.ai/keys) • [Fireworks](https://fireworks.ai/api-keys) • [Mistral](https://console.mistral.ai/api-keys) • [DeepInfra](https://deepinfra.com/dash/api_keys) • [HuggingFace](https://huggingface.co/settings/tokens)

---

## Demo

```bash
$ evidence-guardian demo
```

```
┌──────────────────────────────────────────────────────────────┐
│              EvidenceGuardian Demo Mode                       │
│                                                               │
│  1. Start a local vulnerable Flask app                        │
│  2. Run a full scan against it                                │
│  3. Generate an HTML evidence report                          │
│                                                               │
│  No external targets. No API key needed.                      │
└──────────────────────────────────────────────────────────────┘

  Running ssrf... ---------------------------------------- 100%
  Running idor... ---------------------------------------- 100%
  Running xss...  ---------------------------------------- 100%
  Running sqli... ---------------------------------------- 100%
  Running open_redirect... -------------------------------- 100%
  Running deep_exploit... --------------------------------- 100%
  Running auth_scan... ------------------------------------ 100%
  Running endpoint_discovery... --------------------------- 100%

============================================================
EvidenceGuardian Scan Report
============================================================
Target: http://127.0.0.1:5000
Duration: 12.7s
Modules: ssrf, idor, xss, sqli, open_redirect, deep_exploit, auth_scan, endpoint_discovery
LLM: mock-deterministic

Findings: 12 total, 12 proven

┌─────────────┬────────────┬──────────┬───────────────────────────────────┬────────┐
│ ID          │ Type       │ Severity │ Endpoint                          │ Proven │
├─────────────┼────────────┼──────────┼───────────────────────────────────┼────────┤
│ EG-SQLI-001 │ SQLi       │ CRITICAL │ http://127.0.0.1:5000/api/login   │   ✓    │
│ EG-SSRF-001 │ SSRF       │ HIGH     │ http://127.0.0.1:5000/api/fetch   │   ✓    │
│ EG-IDOR-001 │ IDOR       │ HIGH     │ http://127.0.0.1:5000/api/users/1 │   ✓    │
│ EG-XSS-001  │ XSS        │ MEDIUM   │ http://127.0.0.1:5000/search      │   ✓    │
│ EG-REDIRECT │ OPEN_REDIR │ MEDIUM   │ http://127.0.0.1:5000/login_redir │   ✓    │
└─────────────┴────────────┴──────────┴───────────────────────────────────┴────────┘

Proven Findings (with evidence):

  EG-SQLI-001: SQL error triggered by payload in id parameter.
    Request: GET http://127.0.0.1:5000/api/login?id='
    Response: 500
    PoC script available

  EG-SSRF-001: Server fetches user-supplied URLs without validation.
    Request: GET http://127.0.0.1:5000/api/fetch?url=http://169.254.169.254/...
    Response: 200
    PoC script available

Report saved to: reports/evidence_guardian_127.0.0.1_5000_20260916.html
```

---

## Modules

| Module | Description | Detection | Proof |
|--------|-------------|-----------|-------|
| **SSRF** | Server-Side Request Forgery | Internal address probes + baseline comparison | AWS metadata exposure proof |
| **IDOR** | Insecure Direct Object Reference | Cross-user data access via ID manipulation | Multi-user response comparison |
| **XSS** | Reflected Cross-Site Scripting | Payload reflection detection | Unencoded payload in response |
| **SQLi** | SQL Injection | Error-based + time-based blind | SQL error in response |
| **Open Redirect** | Unvalidated redirects | External domain redirect chain | Redirect capture |
| **Sensitive Data** | Exposed credentials/files | Path probing for .env, .git, backups | File content exposure |
| **Misconfiguration** | Security headers/debug | Header analysis + debug endpoint probe | Missing security headers |
| **Deep Exploit** | Advanced discovery | Fuzzing, CVE matching, blind injection, auth bypass, file upload | Multiple techniques |
| **Auth Scan** | Authentication security | JWT analysis, session cookies, password reset | Weak config proof |
| **Endpoint Discovery** | API surface mapping | OpenAPI/Swagger parsing, link crawling | Endpoint inventory |

---

## Architecture

```
evidence_guardian/
├── llm.py              # LLM client (OmniRouter integration)
├── core.py             # Data models: Finding, Evidence, ScanTarget, ScanResult
├── scanner.py          # Orchestrator — runs all modules, collects findings
├── reporter.py         # HTML report generator (auto-escaped, XSS-safe)
├── cli.py              # Click CLI: scan, view, demo, info, omni
├── webhook.py          # Slack/Discord/generic webhook notifications
├── rate_limiter.py     # Token-bucket rate limiter for polite scanning
├── custom_module.py    # Pluggable module API (base class + loader)
├── omni.py             # OmniRoute — 9 free AI providers with failover
└── vulns/
    ├── ssrf.py              # SSRF detection + proof generation
    ├── idor.py              # IDOR detection + proof generation
    ├── xss.py               # XSS detection + proof generation
    ├── sqli.py              # SQLi detection + proof generation
    ├── open_redirect.py     # Open redirect detection + proof generation
    ├── sensitive_data.py    # Sensitive file/credential exposure
    ├── misconfiguration.py  # Security header/debug analysis
    ├── deep_exploit.py      # Fuzzing, CVE, blind SQLi, CMDi, path traversal
    ├── auth_scan.py         # JWT, session, password reset, bypass
    └── endpoint_discovery.py # OpenAPI/Swagger parsing, API crawling
```

### How It Works

1. **Target Definition** — Define an authorized scan target with scope
2. **Endpoint Discovery** — Map the API surface (Swagger, crawling, patterns)
3. **Module Execution** — Each vulnerability module probes the target
4. **Evidence Capture** — For each finding, capture HTTP request/response pairs
5. **Proof Generation** — Generate a standalone PoC script (using safe `repr()` quoting)
6. **AI Enrichment** — (Optional) Use OmniRoute to add remediation advice
7. **Report Generation** — Package everything into a self-contained HTML evidence bundle

---

## CLI Reference

### `scan` — Run a security scan

```bash
evidence-guardian scan <url> [options]

Options:
  -s, --scope TEXT       Scope description for the scan
  -m, --modules TEXT     Comma-separated modules
                         [default: ssrf,idor,xss,sqli,open_redirect,sensitive_data,misconfiguration,deep_exploit,auth_scan,endpoint_discovery]
  -w, --webhooks TEXT    Comma-separated webhook URLs for notifications
  -o, --output TEXT      Output directory [default: reports]
  --mock / --no-mock     Force mock LLM mode (no API key needed)
  --open / --no-open     Open HTML report after scan
  --omni / --no-omni     Use OmniRoute for free multi-provider AI routing
  -p, --provider TEXT    Preferred AI provider (ollama, groq, nous, together, openrouter, fireworks, mistral, deepinfra, hf)
  -M, --model TEXT       Specific model to use (provider-specific)
```

### `demo` — Run the local demo

```bash
evidence-guardian demo
```

### `omni` — Show OmniRoute status

```bash
evidence-guardian omni              # list available providers
evidence-guardian omni groq         # test/show models for a provider
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

# Run all tests (17 tests, ~45s)
pytest tests/ -v

# Run specific module tests
pytest tests/test_evidence_guardian.py::TestSSRFModule -v
pytest tests/test_evidence_guardian.py::TestIDORModule -v
pytest tests/test_evidence_guardian.py::TestXSSModule -v
pytest tests/test_evidence_guardian.py::TestSQLiModule -v
pytest tests/test_evidence_guardian.py::TestOpenRedirectModule -v
```

---

## Safety & Ethics

EvidenceGuardian is built for **authorized security testing only**.

- **Scope gating** — Only targets what you explicitly authorize
- **Authorization prompt** — Requires confirmation before scanning
- **No destructive payloads** — SQLi detection uses non-destructive boolean/time-based techniques
- **Rate limiting** — Token-bucket rate limiter for polite scanning
- **Demo mode** — Local vulnerable app for safe testing

**Never use this tool against systems you don't own or have explicit permission to test.**

---

## Philosophy

1. **Every claim must carry proof** — If we can't show it working, we don't report it
2. **Authorized targets only** — Scope gating built into the core
3. **Reproducible by design** — Evidence bundles are self-contained
4. **No hallucination theater** — False positives are flagged, not hidden
5. **Free to use** — OmniRoute provides 9 free AI providers, works offline in mock mode

---

## Roadmap

- [x] Add authentication scanning (JWT, session management)
- [x] Add API endpoint discovery (OpenAPI/Swagger parsing)
- [ ] Add CI/CD integration (GitHub Actions badge on README)
- [x] Add webhook notifications for findings
- [x] Add custom vulnerability module API
- [x] Add rate limiting and polite scanning mode
- [x] Add OmniRoute with 9 free AI providers
- [x] Add Deep Exploit module (fuzzing, CVE, blind injection)
- [ ] Add PDF report export
- [ ] Add GraphQL endpoint discovery
- [ ] Add WebSocket security scanning

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Author

Built by [Achref Ferjani](https://github.com/cy1ingachref) — security researcher, bug bounty hunter, PFE student at ISSATM Bizerte, Tunisia.

---

<div align="center">

**Every finding must carry proof. No proof, no claim.**

If this project helps you, please ⭐ it on GitHub!

</div>
