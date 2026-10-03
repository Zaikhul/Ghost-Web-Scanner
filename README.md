<h1 align="center">💀 GHOST-WEB-SCANNER Framework</h1>
<h3 align="center">v2.0 — Defensive Edition</h3>
<p align="center">
  <em>A high-performance, asynchronous internal security auditing framework<br>designed to identify vulnerabilities and validate infrastructure resilience.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/engine-httpx%20%2F%20HTTP2-green?style=for-the-badge" alt="HTTPX Engine">
  <img src="https://img.shields.io/badge/architecture-async%20modular-purple?style=for-the-badge" alt="Async Modular">
  <img src="https://img.shields.io/badge/license-MIT-orange?style=for-the-badge" alt="MIT License">
</p>

<p align="center">
  <img src="img/1.png" alt="Ghost Scanner Terminal Preview" width="90%" style="border-radius:12px; box-shadow:0 0 25px #ff0000;">
</p>

---

> [!CAUTION]
> **⚠️ AUTHORIZED INTERNAL USE ONLY**
>
> This framework is designed **exclusively** for security auditing of **owned and authorized internal infrastructure**. It is a **defensive tool** — built to identify and remediate vulnerabilities *before* malicious actors exploit them. Any use of this software against systems without **explicit written authorization** is illegal and unethical. The developers assume **no responsibility** for any misuse, unauthorized access, or damage caused by improper use of this tool.
>
> **By using Ghost Scanner, you confirm that you have full authorization to test the target systems.**

---

## 📋 Table of Contents

- [Mission & Purpose](#-mission--purpose)
- [The Evolution: v1.0 → v2.0](#-the-evolution-v10--v20)
- [Defensive Capabilities](#-defensive-capabilities)
- [Project Architecture](#-project-architecture)
- [Installation & Requirements](#-installation--requirements)
- [Usage Guide](#-usage-guide)
- [Understanding the JSON Report](#-understanding-the-json-report)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🎯 Mission & Purpose

Ghost Scanner v2.0 is a **modular defensive security framework** engineered for internal security teams. Its mission is threefold:

| Objective | Description |
|---|---|
| **Identify** | Discover exposed directories, subdomains, misconfigured headers, insecure cookies, and technology fingerprints before attackers do. |
| **Validate** | Verify that security controls — WAF rate-limiting, HSTS enforcement, CSP policies, cookie security flags — are correctly configured and effective. |
| **Stress-Test** | Measure infrastructure resilience under controlled load to validate load balancers and rate-limiting thresholds. |

The framework produces **structured JSON reports** with severity ratings and remediation guidance, enabling seamless integration into CI/CD pipelines and defensive dashboards.

---

## 🔄 The Evolution: v1.0 → v2.0

Ghost Scanner v2.0 is a ground-up architectural refactoring that transforms a monolithic script into a professional-grade security framework.

### Monolith → Modular Architecture

| Aspect | v1.0 (Legacy) | v2.0 (Defensive Edition) |
|---|---|---|
| **Structure** | Single 389-line file | Modular package with 13+ source files across 4 sub-packages |
| **Responsibility** | UI, scanning, networking, and reporting interleaved | Clean separation: `/core`, `/modules`, `/utils`, `/reports` |
| **Extensibility** | Adding a feature requires modifying monolithic class | Drop-in module pattern — add a new file to `/modules/` |
| **Testability** | Impossible to unit-test individual components | Each module is independently testable with mock HTTP clients |

### `requests` → `httpx` with Native Async I/O

The legacy scanner used `requests` (synchronous) inside `asyncio.run_in_executor()` — a workaround that occupied one OS thread per request and created a contention bottleneck between the 500-slot semaphore and the 150-thread pool.

**v2.0** uses [`httpx`](https://www.python-httpx.org/) with native `async/await`:

| Feature | Legacy (`requests`) | v2.0 (`httpx`) |
|---|---|---|
| **Concurrency Model** | Thread-per-request via executor | True async I/O — no thread overhead |
| **HTTP/2 Support** | ❌ None | ✅ Native with `h2` transport |
| **Connection Pooling** | Uncontrolled `Session()` | `httpx.Limits(max_connections, max_keepalive)` |
| **Timeout Granularity** | Single integer timeout | Per-phase: `connect`, `read`, `write`, `pool` |
| **SSL Management** | `verify=False` globally hardcoded | CLI toggle: `--ssl-verify` / `--no-ssl-verify` |

### Bare `except:` → Robust Exception Handling

The legacy codebase contained **7+ bare `except: pass` blocks** that silently swallowed all exceptions — including `KeyboardInterrupt`, `SystemExit`, and `MemoryError`. Debugging was effectively impossible.

**v2.0** handles specific exceptions:

```python
# Every network call now catches specific errors:
except httpx.ConnectTimeout:
    logger.warning("Connect timeout: %s", url)
except httpx.ReadTimeout:
    logger.warning("Read timeout: %s", url)
except httpx.ConnectError:
    logger.warning("Connection refused / DNS failure: %s", url)
except httpx.TooManyRedirects:
    logger.warning("Too many redirects: %s", url)
except httpx.RequestError as exc:
    logger.error("Request error for %s: %s", url, exc)
```

---

## 🛡️ Defensive Capabilities

### Module Overview

| Module | File | Capability |
|---|---|---|
| **Reconnaissance** | `modules/recon.py` | Subdomain enumeration (20+ word list), directory brute-force (20+ paths), WAF detection (Cloudflare, ModSecurity, Sucuri, Akamai, Imperva, AWS WAF), CMS fingerprinting, server tech stack, IP geolocation |
| **Security Header Audit** | `modules/security_headers.py` | CSP (presence + `unsafe-inline`/`unsafe-eval` detection), HSTS (max-age validation, `includeSubDomains`), X-Frame-Options, X-Content-Type-Options, Permissions-Policy, Referrer-Policy |
| **Cookie Security Audit** | `modules/cookie_audit.py` | HttpOnly, Secure, SameSite flag validation with severity escalation for session cookies; SameSite=None-without-Secure detection |
| **Load Resilience Test** | `modules/stress_test.py` | Controlled stress testing with configurable concurrency, duration, and per-request delay. Mandatory `authorized_by_admin=True` safety gate. Hard caps: 200 workers, 300s duration. Graceful shutdown via `asyncio.Event` |

### Security Header Auditor — Deep Dive

The header audit module checks each response against **OWASP recommended security headers**:

```
✓  Content-Security-Policy     → Present, but warns on 'unsafe-inline' / 'unsafe-eval'
✗  Strict-Transport-Security   → MISSING — remediation: add max-age=31536000
✓  X-Frame-Options             → SAMEORIGIN
✗  X-Content-Type-Options      → MISSING — remediation: add nosniff
~  Permissions-Policy          → MISSING — remediation: restrict geolocation, camera
✓  Referrer-Policy             → strict-origin-when-cross-origin
```

Each finding includes a **severity rating** (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`) and **specific remediation guidance**.

### Cookie Security Auditor — Deep Dive

The cookie module parses raw `Set-Cookie` headers and applies heuristic session detection:

| Check | Impact | Severity |
|---|---|---|
| Missing `HttpOnly` on session cookie | XSS cookie theft | `HIGH` |
| Missing `Secure` flag | Transmitted over unencrypted HTTP | `HIGH` |
| Missing `SameSite` attribute | Cross-Site Request Forgery (CSRF) | `MEDIUM` |
| `SameSite=None` without `Secure` | Browser will reject the cookie | `HIGH` |

### Load Resilience Module — Safety Architecture

The stress test module (formerly V60) has been redesigned with multiple safety layers:

```
┌───────────────────────────────────────────────────────┐
│              SAFETY GATE (Layer 1)                     │
│   authorized_by_admin=True  ── REQUIRED ──  or HALT   │
├───────────────────────────────────────────────────────┤
│              HARD CAPS (Layer 2)                       │
│   Max Workers: 200  │  Max Duration: 300s              │
│   Min Delay: 0.01s  │  Politeness enforced             │
├───────────────────────────────────────────────────────┤
│            GRACEFUL SHUTDOWN (Layer 3)                  │
│   asyncio.Event → workers drain → metrics reported     │
│   Ctrl+C handled cleanly — no orphaned connections     │
└───────────────────────────────────────────────────────┘
```

### JSON Reporting Engine

The legacy scanner appended raw SQL `INSERT` statements to a `.sql` file — a fragile approach vulnerable to SQL injection from crafted server responses. 

**v2.0** replaces this with a structured **JSON reporting system**:

| Aspect | Legacy `.sql` | v2.0 JSON |
|---|---|---|
| **Format** | SQL INSERT strings | Structured JSON with schema |
| **Safety** | Vulnerable to SQL injection | Data-only serialisation, no code execution |
| **Integration** | Manual database import | Parseable by Splunk, ELK, Jira, CI/CD pipelines |
| **Content** | Category + detail only | `timestamp`, `severity`, `category`, `target_url`, `detail`, `remediation` |

---

## 🏗️ Project Architecture

```
GHOST-WEB-SCANNER/
│
├── ghost_scanner/                    # Main Python package
│   ├── __init__.py                   # Package metadata (version, author)
│   ├── __main__.py                   # CLI entry point (argparse)
│   │
│   ├── core/                         # Engine & configuration
│   │   ├── __init__.py
│   │   ├── config.py                 # ScanConfig, URL validation, SSRF prevention
│   │   └── engine.py                 # Orchestrator: wires modules → findings → report
│   │
│   ├── modules/                      # Scan modules (plug-and-play)
│   │   ├── __init__.py
│   │   ├── recon.py                  # Subdomain enum, directory brute, WAF/CMS fingerprint
│   │   ├── security_headers.py       # CSP, HSTS, X-Frame-Options, X-Content-Type audit
│   │   ├── cookie_audit.py           # HttpOnly, Secure, SameSite validation
│   │   └── stress_test.py            # Load resilience with safety gate
│   │
│   ├── utils/                        # Shared utilities
│   │   ├── __init__.py
│   │   ├── http_client.py            # httpx AsyncClient wrapper (HTTP/2, pooling)
│   │   ├── banner.py                 # ASCII skull banner, progress bar, UI helpers
│   │   └── ui.py                     # Structured logging (ANSI colours, file output)
│   │
│   └── reports/                      # Report generation
│       ├── __init__.py
│       └── json_report.py            # Finding dataclass, ScanReport, JSON export
│
├── requirements.txt                  # httpx[http2], beautifulsoup4, lxml
├── README.md                         # This document
├── LICENSE                           # MIT License
├── CONTRIBUTING.md                   # Contribution guidelines
├── memory.md                         # Technical audit & codebase analysis
│
├── Ghost-Web-Scanner.py              # [LEGACY] v1.0 monolithic scanner
└── Ghost-Web-Scanner-V1.0.py         # [LEGACY] v1.0 enhanced monolithic scanner
```

---

## ⚙️ Installation & Requirements

### Prerequisites

| Requirement | Version |
|---|---|
| Python | `3.11+` |
| pip | Latest |
| Git | Any |

### Dependencies

| Package | Purpose |
|---|---|
| `httpx[http2]` | Async HTTP client with HTTP/2 and connection pooling |
| `beautifulsoup4` | HTML parsing for form and link extraction |
| `lxml` | High-performance HTML/XML parser backend |

### Step-by-Step Setup

**1. Clone the repository**
```bash
git clone https://github.com/Sneijderlino/Ghost-Web_Scanner.git
cd Ghost-Web_Scanner
```

**2. Create and activate a virtual environment**
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

**3. Install dependencies**
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

**4. Verify installation**
```bash
python -m ghost_scanner --version
# Output: Ghost Scanner v2.0.0
```

---

## 🚀 Usage Guide

### CLI Reference

```
python -m ghost_scanner [OPTIONS]
```

| Flag | Short | Default | Description |
|---|---|---|---|
| `--target` | `-t` | *(required)* | Target URL (e.g., `https://example.com`) |
| `--modules` | `-m` | `recon headers cookies` | Modules to run: `recon`, `headers`, `cookies`, `stress` |
| `--timeout` | | `10.0` | Per-request timeout in seconds |
| `--ssl-verify` | | `True` | Enable TLS certificate verification |
| `--no-ssl-verify` | | | Disable TLS certificate verification |
| `--allow-private` | | `False` | Allow scanning of RFC-1918 private IPs |
| `--concurrency` | `-c` | `50` | Maximum concurrent async requests |
| `--output` | `-o` | Auto-generated | Output path for the JSON report |
| `--version` | `-V` | | Show version and exit |

### Example 1 — Standard Reconnaissance

Perform subdomain enumeration, directory brute-force, and technology fingerprinting:

```bash
python -m ghost_scanner -t https://target.internal.corp -m recon
```

### Example 2 — Full Defensive Audit

Run all passive security checks — reconnaissance, header audit, and cookie audit:

```bash
python -m ghost_scanner \
    --target https://target.internal.corp \
    --modules recon headers cookies \
    --output reports/full_audit.json
```
```
python -m ghost_scanner --target https://www.heykull-tech.cloud --modules recon headers cookies --output reports/full_audit.json
```

### Example 3 — Internal Infrastructure (Private IPs)

Scan an internal service on a private network:

```bash
python -m ghost_scanner \
    --target http://10.0.1.50:8080 \
    --allow-private \
    --no-ssl-verify \
    --modules recon headers cookies
```
```
python -m ghost_scanner --target http://34.50.97.245:8080 --allow-private --no-ssl-verify --modules recon headers cookies --output reports/full_audit.json
```

### Example 4 — Load Resilience / Stress Test

Validate WAF rate-limiting and load balancer stability on an authorized internal target:

```bash
python -m ghost_scanner \
    --target https://staging-lb.internal.corp \
    --modules stress \
    --concurrency 100 \
    --allow-private
```
```
python -m ghost_scanner --target https://www.heykull-tech.cloud --modules stress --concurrency 100 --output reports/stress_test.json
```

> [!IMPORTANT]
> The `stress` module will **only execute** if the internal `authorized_by_admin=True` safety gate is satisfied. This is enforced programmatically by the `StressTestModule.safety_check()` method. The module includes hard caps: **200 max workers** and **300 seconds max duration**.

### Example 5 — Self-Signed Certificate Environments

For staging environments with self-signed certificates:

```bash
python -m ghost_scanner \
    --target https://staging.internal.corp \
    --no-ssl-verify \
    --output staging_audit.json
```

---

## 📊 Understanding the JSON Report

Every scan produces a structured JSON report. Here is the schema:

```json
{
  "scan_metadata": {
    "scanner": "Ghost Scanner v2.0",
    "scan_start": "2026-03-27T01:00:00+00:00",
    "scan_end": "2026-03-27T01:02:35+00:00",
    "target_url": "https://target.internal.corp",
    "domain": "target.internal.corp",
    "target_ip": "10.0.1.50",
    "risk_score": 65
  },
  "summary": {
    "CRITICAL": 0,
    "HIGH": 3,
    "MEDIUM": 4,
    "LOW": 2,
    "INFO": 8
  },
  "total_findings": 17,
  "findings": [
    {
      "timestamp": "2026-03-27T01:01:12+00:00",
      "severity": "HIGH",
      "category": "MISSING_HEADER",
      "target_url": "https://target.internal.corp",
      "detail": "Content-Security-Policy header is missing.",
      "remediation": "Add a Content-Security-Policy header: default-src 'self'"
    }
  ]
}
```

### Severity Breakdown

| Severity | Weight | Meaning |
|---|---|---|
| `CRITICAL` | 45–50 pts | Immediate exploitation risk (auth bypass, critical SQLi) |
| `HIGH` | 25–40 pts | Significant vulnerability (missing CSP, insecure session cookies) |
| `MEDIUM` | 15–20 pts | Defence-in-depth gap (missing X-Frame-Options, no SameSite) |
| `LOW` | 5–10 pts | Informational concern (short HSTS max-age, missing Referrer-Policy) |
| `INFO` | 3–5 pts | Reconnaissance data (server type, geolocation, subdomains) |

The **Risk Score** is a weighted aggregate (0–100%) of all findings, capped at 100.

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Implement your changes following the modular architecture
4. Ensure PEP 8 compliance and type hints on all public methods
5. Submit a Pull Request with a clear description

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

---

## 📝 License

Ghost Scanner is licensed under the [MIT License](LICENSE).

---

<p align="center">
  <strong>💀 Ghost Scanner v2.0 — Defend First. Audit Always. Stay Ethical. 💀</strong>
</p>
