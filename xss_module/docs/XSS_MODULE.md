# XSS Detection Module

Production-minded Cross-Site Scripting detection for the modular web vulnerability scanner (authorized lab / graduation project use).

## Architecture

```
crawl_map.json
    → InputAdapter (validate, normalize, dedupe)
    → ScopeController (fail closed on every request/redirect)
    → HttpEngine (budget, timeouts, size limits, UA)
    → Marker + Reflection engine
    → ContextAnalyzer (HTML body / attr / JS / URL / comment)
    → Verification (opt-in metachar probes + optional Playwright)
    → StoredXSSEngine (opt-in submit + retrieve)
    → FindingManager (confidence, severity, dedupe)
    → ScanResult (JSON-compatible)
```

Primary entry points:

- CLI / import: `xss_module.py`
- Package API: `xss.engine.run_xss_scan`
- Main scanner: `scanner/main.py`

## Safety model

- Explicit `--origin` / `allowed_origins` required. Crawl-map URLs are **not** authorization.
- Loopback and private networks blocked unless `--allow-loopback` / `--allow-private`.
- Cloud metadata hosts always blocked.
- Marker-only mode is the default.
- Active verification, metachar probes, stored XSS, and browser verification are **opt-in**.
- Credentials/cookies redacted from logs.
- No third-party callbacks; browser verification uses an in-page signal only.

## Modes

| Mode | Flag | Behavior |
|------|------|----------|
| Marker-only | default / `--marker-only` | Unique alphanumeric markers; candidates only |
| Active verify | `--active-verify` | Enables further verification features |
| Metachar probes | `--metachar-probes` | Context-sensitive breakout probes |
| Extended probes | `--extended-probes` | Extra curated probes from educational catalog (budgeted) |
| Stored XSS | `--enable-stored-xss` | Submit marker + fetch `renders_to` pages |
| Browser verify | `--browser-verify` | Playwright execution signal (optional dep) |

### Educational payload catalog

Context-mapped lab probes in `xss/payload_catalog.py` are adapted from
[payload-box/xss-payload-list](https://github.com/payload-box/xss-payload-list)
(Basic event-handlers / script-tags, Context-Guide, encoding notes).

Intentionally **not** imported: All-In-One dumps, Blind/XSS-Hunter callbacks,
WAF-bypass spraying lists, or cookie-exfiltration demos. Upstream `alert(1)`
examples are replaced with unique in-page signals or short reflection probes.

## Finding schema

Each finding includes: `id`, `vulnerability_type` (`xss.reflected` / `xss.stored`), `title`, `url`, `method`, `parameter`, `input_type`, `context`, `payload_or_probe_id`, `evidence`, `detection_method`, `confidence`, `severity`, `verification_status`, `http_status`, `cwe` (CWE-79), `owasp` (A03:2021), `description`, `impact`, `remediation`, `references`, `timestamp`, `confidence_reasons`.

### Verification status

- `candidate` — reflection evidence without exploit proof
- `probable` — context-appropriate metacharacters reflected raw
- `confirmed` — browser execution signal observed
- `rejected_safe` — encoded/inert (reported as outcomes, not findings)
- `inconclusive` / `failed` — timeouts, errors, scope issues

## Installation

```bash
cd xss_module
python -m pip install -r requirements.txt
# Optional browser verification:
# python -m pip install playwright && playwright install chromium
```

## Run against your authorized local website

VulnSight does not ship a vulnerable app. Start your own prepared local target first.

```bash
# Terminal 1 — your authorized local website on http://127.0.0.1:5001

# Terminal 2 (from xss_module/)
python xss_module.py \
  --crawl-map fixtures/sample_crawl_map.json \
  --origin http://127.0.0.1:5001 \
  --allow-loopback \
  --active-verify --metachar-probes \
  --enable-stored-xss \
  -o findings.json -v
```

Programmatic:

```python
from xss_module import run_xss_module

result = run_xss_module(
    crawl_map_path="fixtures/sample_crawl_map.json",
    allowed_origins=["http://127.0.0.1:5001"],
    allow_loopback=True,
    marker_only=False,
    enable_active_verification=True,
    enable_metachar_probes=True,
    enable_stored_xss=True,
)
print(result.to_dict())
```

## Tests

```bash
pytest -q
```

## Known limitations

- DOM-based XSS is **not** implemented in the core pipeline.
- Browser verification is optional and GET-oriented for execution checks.
- Stored XSS requires `renders_to` relationships from the external crawl map / Recon output; missing links are reported as limitations, not “safe”.
- Absence of reflection ≠ proof of safety.
- Framework-specific sinks, mXSS, mutation XSS, and complex template contexts are out of scope.
- Multipart file uploads and JSON API bodies are not fully tested injection surfaces.

## References

- [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP Top 10 2021 A03 Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger XSS Academy](https://portswigger.net/web-security/cross-site-scripting)
- [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/)
- [payload-box/xss-payload-list](https://github.com/payload-box/xss-payload-list) (educational probe patterns)
