# 🔍 GHOST-WEB-SCANNER — Technical Audit & Memory Document

> **Audit Date:** 2026-03-27  
> **Auditor:** Senior Python Engineer & Cybersecurity Specialist  
> **Scope:** Full codebase review — architecture, security, performance, and code quality  
> **Verdict:** Functional prototype with **critical** code-quality and security issues requiring refactoring before any production or responsible-disclosure usage.

---

## 1. Purpose

### 1.1 Core Objective

Ghost-Web-Scanner is a **terminal-based, offensive web security reconnaissance and vulnerability assessment tool** written in Python. It is designed to run on **Kali Linux, Termux (Android), and Windows**, targeting web applications to discover:

- Exposed directories and sensitive files (`.env`, `.git/config`, `backup.zip`, etc.)
- Subdomains via DNS enumeration
- Server technology fingerprinting (Web Server, WAF, CMS detection)
- Geolocation of the target IP

### 1.2 Targeted Vulnerability Classes

| Vulnerability Class | Detection Method | File(s) |
|---|---|---|
| **SQL Injection (SQLi)** | Error-based, Time-based Blind, Boolean-based, Union-based | `V1.0.py` → `run_v51()` |
| **NoSQL Injection** | JSON payload with MongoDB `$gt`, `$ne` operators | `V1.0.py` → `run_v51()` |
| **Cross-Site Scripting (XSS)** | Reflected payload detection (`<script>`, `<svg>`) | `Ghost-Web-Scanner.py` → `scan_params()`, `V1.0.py` → `run_v51()` |
| **Local File Inclusion (LFI)** | Path traversal payload (`../../../../etc/passwd`) | `V1.0.py` → `run_v51()` |
| **CSRF Absence** | Missing CSRF token detection on POST forms | `Ghost-Web-Scanner.py` → `form_hunter()` |
| **Sensitive Directory Exposure** | HTTP brute-force on common paths | Both files |
| **Header Injection / Blind SQLi** | Time-based injection via HTTP headers (`User-Agent`, `X-Forwarded-For`, `Referer`) | `V1.0.py` → `run_v55()` |
| **Weak Authentication** | Login forms using GET method, auth bypass payloads | Both files |
| **Denial of Service (DoS)** | High-volume packet flooding (V60 module) | `V1.0.py` → `run_v60()` |

---

## 2. Directory Project

```
GHOST-WEB-SCANNER/
├── .git/                          # Git version control metadata
├── .gitignore                     # Ignores __pycache__, .env, venv/, IDE configs
├── CONTRIBUTING.md                # Contribution guidelines (Indonesian)
├── LICENSE                        # MIT License
├── README.md                      # Project documentation with installation guides
├── requirements.txt               # Python dependencies (requests, beautifulsoup4, urllib3)
│
├── Ghost-Web-Scanner.py           # V47 — Original scanner (278 lines, single-pass)
├── Ghost-Web-Scanner-V1.0.py      # V75 — Enhanced scanner (389 lines, menu-driven)
│
├── Ghost_Breaker_Report.sql       # SQL-formatted scan logs (auto-generated)
├── Ghost_Breaker_Report.txt       # Plain-text scan logs (auto-generated)
│
├── img/                           # Screenshots for README
├── img-2/                         # Additional screenshots
└── venv/                          # Python virtual environment (gitignored)
```

### Key File Responsibilities

| File | Role |
|---|---|
| `Ghost-Web-Scanner.py` | **Legacy scanner (V47):** Linear, single-execution flow — recon → directory brute → form audit → param testing → report. Simpler but less feature-rich. |
| `Ghost-Web-Scanner-V1.0.py` | **Current scanner (V75):** Menu-driven with modular scan phases (V47 Recon, V51 SQLi, V55 Header Injection, V60 DoS). Adds payload mutation, dual-format logging (SQL + TXT), risk scoring, and async concurrency with `asyncio.Semaphore(500)`. |
| `requirements.txt` | Declares 3 dependencies: `requests`, `beautifulsoup4`, `urllib3`. |
| `Ghost_Breaker_Report.sql` | Auto-appended SQL INSERT statements for each finding — intended for database import. |
| `Ghost_Breaker_Report.txt` | Human-readable timestamped log of all findings. |

---

## 3. Functions

### 3.1 V75 (`Ghost-Web-Scanner-V1.0.py`) — Class `GhostOmniSuite`

#### Initialization & Utilities

| Method | Purpose |
|---|---|
| `__init__()` | Initializes session, semaphore (500), thread pool (150 workers), logging paths, and state variables. |
| `get_sys_info()` | Retrieves local IP, device model, and battery status (Termux-specific). |
| `banner(mode)` | Renders the ASCII art banner with target intel, risk level, and system info. |
| `write_logs(category, detail)` | Appends findings to both `.sql` and `.txt` log files with timestamps. |
| `calculate_risk()` | Computes a weighted risk score (0–100%) based on vulnerability categories found. |
| `mutate_payload(payload)` | Applies one of 10 random obfuscation techniques (hex, URL-encode, Base64, case alternation, MySQL version wrap, etc.) to evade WAF. |

#### Core Scanning Modules

```
┌─────────────────────────────────────────────────────────────────┐
│                        USER INPUT (URL)                        │
│                              │                                  │
│                    ┌─────────▼──────────┐                      │
│                    │   main_menu()       │                      │
│                    │   Target Resolution │                      │
│                    │   DNS → IP Lookup   │                      │
│                    └─────────┬──────────┘                      │
│             ┌────────┬───────┼───────┬────────┐                │
│             ▼        ▼       ▼       ▼        ▼                │
│         run_v47  run_v51  run_v55  run_v60  show_results       │
│         (Recon)  (SQLi)  (Header) (DoS)   (Report)            │
│             │        │       │       │        │                │
│             ▼        ▼       ▼       ▼        ▼                │
│         write_logs() ──────────────────► .sql / .txt           │
└─────────────────────────────────────────────────────────────────┘
```

| Module | Method | Logic |
|---|---|---|
| **V47 — Recon Force** | `run_v47()` | 1. Calls `get_target_intel()` for IP geolocation, WAF detection, and tech stack fingerprinting. 2. Enumerates 9 subdomains via HTTP probing. 3. Brute-forces 12 common directory paths, logging `200`/`403`/`405` responses. |
| **V51 — SQL GOD-MODE** | `run_v51()` | 1. Fetches target page and parses all `<form>` elements with BeautifulSoup. 2. Iterates 9 payloads (SQLi, NoSQL, LFI, XSS) per input field. 3. Applies `mutate_payload()` for WAF evasion. 4. Detects error-based SQLi via keyword matching, time-based via response delay (>4s), and boolean-based via response length diff. 5. Concurrently sends NoSQL `$ne` probe. |
| **V55 — Header God-Force** | `run_v55()` | 1. Crawls internal links from the target page. 2. Sends crafted SQLi payloads in `User-Agent`, `X-Forwarded-For`, and `Referer` headers. 3. Detects blind SQLi via time-based delay (>=5s). |
| **V60 — Omni-Void** | `run_v60()` | 1. Accepts intensity parameter (100–500 threads). 2. Sends continuous POST requests with junk data until `Ctrl+C`. 3. **This is a DoS/stress-testing module.** |
| **Report** | `show_results()` | Displays aggregated intelligence: target info, firewall, tech stack, risk score, vulnerability breakdown with category counts, and recommendations. |

#### Async Infrastructure

| Method | Purpose |
|---|---|
| `fetch(url, params, method, timeout, json_data, headers)` | Central HTTP request dispatcher. Wraps `requests.Session` calls inside `asyncio.run_in_executor()` with the `ThreadPoolExecutor`. Applies random `User-Agent` and spoofed `X-Forwarded-For`. |
| `sync_bar(duration, label, task)` | Renders an animated ASCII progress bar while awaiting an `asyncio.Task`. |

### 3.2 V47 (`Ghost-Web-Scanner.py`) — Class `GhostHunterV47`

The legacy version follows a **linear pipeline**: `start()` → `get_target_intel()` → `subdomain_hunter()` → directory brute → `form_hunter()` → `scan_params()` → inline report.

Notable differences from V75:
- No payload mutation.
- No menu system (single sequential run).
- No dual-format logging (results displayed inline only).
- Simpler `fetch()` — no semaphore, no thread pool customization.
- Includes `form_hunter()` which detects CSRF token absence and GET-method login forms (removed in V75).

---

## 4. Advantages (Strengths)

### 4.1 Architecture & Design

| Strength | Details |
|---|---|
| **Async + ThreadPoolExecutor hybrid** | Using `asyncio.Semaphore(500)` with `ThreadPoolExecutor(max_workers=150)` provides controlled concurrency. The blocking `requests` library is properly offloaded to the executor, preventing event loop starvation. |
| **Payload mutation engine** | `mutate_payload()` offers 10 obfuscation variants (hex encoding, Base64, MySQL version wrap, case alternation), which is a meaningful WAF evasion strategy for a CLI tool. |
| **Weighted risk scoring** | `calculate_risk()` assigns differentiated weights per category (e.g., `AUTH_BYPASS: 50`, `SQL_TIME_BASED: 48`, `INFO: 5`), producing a more nuanced risk assessment than simple counting. |
| **Dual logging format** | Writing to both `.sql` (for database import) and `.txt` (for human review) is a thoughtful approach for post-scan analysis. |
| **Multi-platform support** | Graceful detection of Termux, Kali, and Windows environments with fallback behavior for platform-specific features (battery, device model). |

### 4.2 Scanning Capabilities

| Strength | Details |
|---|---|
| **Multi-vector SQLi detection** | Covers error-based, time-based blind, boolean-based, and Union-based injection — a solid baseline for automated detection. |
| **NoSQL injection testing** | Including MongoDB `$gt`/`$ne` operator injection is uncommon in lightweight scanners and shows awareness of modern backend stacks. |
| **Header injection module (V55)** | Testing injection via `User-Agent`, `X-Forwarded-For`, and `Referer` headers targets a frequently overlooked attack surface. |
| **CSRF detection (V47)** | `form_hunter()` checking for CSRF token absence on POST forms is a valuable security-hygiene check. |
| **Graceful error handling at entry** | The `try/except ImportError` for BeautifulSoup provides a user-friendly error message instead of a raw traceback. |

### 4.3 User Experience

| Strength | Details |
|---|---|
| **Engaging terminal UI** | The ASCII skull banner with real-time system info (IP, battery, target, risk level) creates an immersive pentesting experience. |
| **Progress bars** | `sync_bar()` provides visual feedback during scans, improving UX for long-running operations. |
| **Structured final report** | `show_results()` provides a well-formatted summary with categorized vulnerability breakdowns and actionable recommendations. |

---

## 5. Disadvantages (Weaknesses & Security Audit)

### 5.1 🔴 CRITICAL — Security Vulnerabilities in the Scanner's Own Code

> [!CAUTION]
> These issues represent security risks in the tool itself, not in targets being scanned.

| # | Issue | Severity | Location | Details |
|---|---|---|---|---|
| **C1** | **SQL Injection in own log file** | 🔴 Critical | `write_logs()` L62–64 | The SQL log uses string interpolation with only single-quote escaping (`replace("'", "''")`). If log output is ever imported into a real database, crafted responses from malicious targets could inject arbitrary SQL. **Fix:** Use parameterized queries or escape all SQL metacharacters properly. |
| **C2** | **SSL verification globally disabled** | 🔴 Critical | L12, L141–144 | `verify=False` on all requests + `urllib3.disable_warnings()` silently suppresses certificate errors. A MITM attacker could intercept all scanner traffic. **Fix:** Make `verify=False` opt-in via a `--insecure` CLI flag, and warn the user when used. |
| **C3** | **No input validation on URL** | 🟠 High | `main_menu()` L360–362 | User-supplied URLs are blindly prefixed with `http://` if they don't start with `"http"`. No validation for malformed URLs, `file://` protocol, or localhost targets. **Fix:** Use `urllib.parse.urlparse()` to validate scheme, netloc, and reject dangerous protocols. |
| **C4** | **Uncontrolled DoS module (V60)** | 🟠 High | `run_v60()` L288–308 | The flood module has no rate limiting, no duration cap, no legal disclaimer confirmation, and no cool-down. Running this against an unauthorized target is illegal in most jurisdictions. **Fix:** Add explicit legal consent prompt, configurable duration limit, and rate-limiting. |
| **C5** | **IP spoofing via X-Forwarded-For** | 🟠 High | `fetch()` L133 | Every request sends a randomized `X-Forwarded-For` header. This is essentially IP spoofing, which may violate network policies and cause legal issues. **Fix:** Make this behavior opt-in via a `--spoof-ip` flag. |
| **C6** | **Leaked target data in report files** | 🟡 Medium | `write_logs()` | Report files (`Ghost_Breaker_Report.sql/txt`) are written to the CWD without encryption. Sensitive target data (URLs, vulnerabilities found) is stored in plaintext. **Fix:** Use a dedicated output directory, support encryption, and add `.gitignore` entries for report files. |
| **C7** | **Raw `shell=True` subprocess calls** | 🟡 Medium | `get_sys_info()` L46–48 | `subprocess.call("command -v ...", shell=True)` and `subprocess.getoutput()` are vulnerable to command injection if any variable is ever interpolated into the command. Currently safe since commands are static, but fragile. **Fix:** Use `subprocess.run()` with list arguments instead of shell strings. |

### 5.2 🟡 Code Quality & "Code Smells"

| # | Issue | Location | Details |
|---|---|---|---|
| **Q1** | **Monolithic single-file architecture** | Both files | The entire application (UI, scanning logic, networking, reporting, payload engine) lives in one file. This violates Separation of Concerns and makes testing impossible. **Fix:** Refactor into a package: `scanner/`, `payloads/`, `reporting/`, `ui/`, `utils/`. |
| **Q2** | **Bare `except:` clauses** | L45, L52, L147, L179, L286, L293, L308 | At least 7 bare `except:` or `except: pass` blocks silently swallow all exceptions, including `KeyboardInterrupt`, `SystemExit`, and `MemoryError`. This makes debugging nearly impossible. **Fix:** Catch specific exceptions (`requests.RequestException`, `socket.gaierror`, etc.) and log errors. |
| **Q3** | **PEP 8 violations** | Throughout | Multiple imports on a single line (L1), inconsistent naming (mixed Indonesian/English), missing docstrings, lines exceeding 120 characters, and single-letter variable names (`r`, `s`, `p`, `h`, `t`). **Fix:** Run `ruff` or `flake8` and enforce a linting configuration. |
| **Q4** | **Duplicate code between V47 and V75** | Both files | `banner()`, `get_sys_info()`, `fetch()`, `sync_bar()`, `get_target_intel()` are duplicated with minor variations. **Fix:** Unify into a single codebase with versioned feature flags. |
| **Q5** | **No type hints** | Throughout | Zero type annotations across 667 lines of code. This prevents static analysis tools (`mypy`, `pyright`) from catching bugs. **Fix:** Add type hints to all method signatures and key variables. |
| **Q6** | **Magic numbers and hardcoded values** | Throughout | Semaphore limit (500), thread pool (150), timeout (7), risk weights, subdomain lists, directory lists — all hardcoded. **Fix:** Extract to a `config.py` or YAML configuration file. |
| **Q7** | **No unit tests** | Project-wide | Zero test files exist. No CI/CD pipeline. **Fix:** Add `pytest` tests for payload mutation, risk calculation, URL parsing, and mock-based HTTP tests. |
| **Q8** | **Synchronous `requests` in async context** | `get_target_intel()` L164 | `requests.get()` is called directly (not via executor) for the IP geolocation API, blocking the event loop. **Fix:** Route through the existing `fetch()` method or switch to `httpx` with native async support. |

### 5.3 🔵 Performance Bottlenecks

| # | Issue | Location | Details |
|---|---|---|---|
| **P1** | **`requests` library in async context** | `fetch()` | Using `requests` (synchronous) inside `run_in_executor()` is a workaround, not a solution. Each request occupies a thread from the pool. With 500 semaphore slots but only 150 threads, there's a contention bottleneck. **Fix:** Migrate to `httpx[http2]` or `aiohttp` for true async I/O. |
| **P2** | **Sequential subdomain scanning** | `run_v47()` L188–192 | Subdomains are tested one at a time with `await` per subdomain. With 9 subdomains, this takes 9× longer than necessary. **Fix:** Use `asyncio.gather()` to probe all subdomains concurrently. |
| **P3** | **No connection pooling control** | `requests.Session()` | The session has no configured `max_retries`, `pool_connections`, or `pool_maxsize` adapter. Under high concurrency (V60), this causes connection leaks. **Fix:** Mount a custom `HTTPAdapter` with appropriate pool sizes. |
| **P4** | **BeautifulSoup with `html.parser`** | `run_v51()`, `run_v55()` | The built-in `html.parser` is 2–5× slower than `lxml`. For large pages, this adds unnecessary latency. **Fix:** Add `lxml` to `requirements.txt` and use `BeautifulSoup(html, "lxml")`. |

### 5.4 🟣 Missing Features (Industry-Standard Gap Analysis)

| Feature | Status | Industry Tools Reference |
|---|---|---|
| **CLI argument parser** | ❌ Missing | All major tools (`nikto`, `sqlmap`, `nuclei`) use `argparse` or `click` for non-interactive operation, scripting, and CI/CD integration. |
| **SSRF detection** | ❌ Missing | No out-of-band (OOB) callback testing for Server-Side Request Forgery. Tools like `nuclei` use Interactsh for this. |
| **CORS misconfiguration** | ❌ Missing | No check for `Access-Control-Allow-Origin: *` or reflected origin headers. |
| **Open redirect detection** | ❌ Missing | No testing of redirect parameters (`?next=`, `?url=`, `?redirect=`). |
| **Cookie security audit** | ❌ Missing | No check for `HttpOnly`, `Secure`, `SameSite` flags on cookies. |
| **Security header analysis** | ❌ Missing | No check for `Content-Security-Policy`, `X-Frame-Options`, `Strict-Transport-Security`, `X-Content-Type-Options`. |
| **Structured output** | ❌ Missing | No JSON/XML/HTML report export. The `.sql` format is non-standard and fragile. |
| **Proxy/Tor support** | ❌ Missing | No SOCKS5 or HTTP proxy configuration for anonymization. |
| **Rate limiting / politeness** | ❌ Missing | No configurable delay between requests. Risk of triggering WAF bans or causing unintended DoS. |
| **Crawling depth control** | ❌ Missing | V55 crawls internal links but with no depth limit, visited-set tracking, or robots.txt compliance. |
| **Authenticated scanning** | ❌ Missing | No support for cookie-based or token-based authenticated scanning. |
| **Wordlist customization** | ❌ Missing | Subdomain and directory lists are hardcoded. No support for external wordlist files (e.g., SecLists). |
| **Logging with `logging` module** | ❌ Missing | All output uses `print()`. No log levels, no file rotation, no structured logging. |
| **Virtual environment automation** | ❌ Missing | `requirements.txt` has no pinned versions, risking dependency drift. |

---

## 6. Summary & Recommendations

### Priority Matrix

| Priority | Action Item |
|---|---|
| 🔴 **P0 — Immediate** | Fix bare `except:` clauses, add URL input validation, add SSL verification toggle, fix SQL log injection risk. |
| 🟠 **P1 — Short-term** | Refactor into a multi-file package, add `argparse` CLI, migrate to `httpx`/`aiohttp`, add type hints. |
| 🟡 **P2 — Medium-term** | Add unit tests with `pytest`, implement security header checks, CORS audit, cookie flags audit, structured JSON output. |
| 🔵 **P3 — Long-term** | Add proxy support, authenticated scanning, external wordlist support, SSRF/open redirect detection, CI/CD pipeline with linting. |

### Library Recommendations

| Current | Recommended | Reason |
|---|---|---|
| `requests` (sync) | `httpx[http2]` | Native async/await, HTTP/2, connection pooling, same API as `requests`. |
| `html.parser` | `lxml` | 2–5× faster HTML parsing, better malformed HTML handling. |
| `print()` | `logging` + `rich` | Structured log levels, file rotation, and beautiful terminal formatting. |
| *(none)* | `argparse` / `click` | CLI argument parsing for non-interactive, scriptable usage. |
| *(none)* | `pydantic` | Settings/config validation with type safety. |

---

> *This document serves as a living reference for the Ghost-Web-Scanner project. It should be updated as the codebase evolves.*
