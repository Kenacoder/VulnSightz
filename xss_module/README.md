# XSS Module

Cross-Site Scripting detection for VulnSight — reflected and stored XSS with marker-first analysis, context classification, scope enforcement, and optional active verification.

## Features

- Consumes Recon `crawl_map.json` (external recon; not bundled)
- Marker-first reflection detection
- HTML body / attribute / JavaScript / URL / comment contexts
- Opt-in metachar probes, extended educational probes, stored XSS, browser verify
- Fail-closed scope (explicit `--origin`, optional loopback/private)
- Structured findings (`CWE-79`, OWASP A03:2021) compatible with the reporting module

## Setup

```bash
cd xss_module
python -m pip install -r requirements.txt
```

## Run (against your authorized local website)

```bash
# Terminal A — start YOUR prepared local target on http://127.0.0.1:5001

# Terminal B
python xss_module.py \
  --crawl-map fixtures/sample_crawl_map.json \
  --origin http://127.0.0.1:5001 \
  --allow-loopback \
  --active-verify --metachar-probes --extended-probes \
  --enable-stored-xss \
  -o findings_xss.json -v
```

Or from the repository root with the full scanner:

```bash
vulnsight init-project -o myproject.json --target http://127.0.0.1:5001
vulnsight scan --project myproject.json
```

## Programmatic API

```python
from xss_module import run_xss_module

result = run_xss_module(
    crawl_map_path="fixtures/sample_crawl_map.json",
    allowed_origins=["http://127.0.0.1:5001"],
    allow_loopback=True,
)
print(result.to_dict())
```

## Tests

```bash
pytest -q
```

## Docs

- [XSS_MODULE.md](docs/XSS_MODULE.md)
- [CRAWL_MAP_SCHEMA.md](docs/CRAWL_MAP_SCHEMA.md)
- [Target guidance](../docs/VULNERABLE_TARGET.md)

## Notes

- Default mode is marker-only (safe). Active verification is opt-in.
- Absence of reflection does not prove an endpoint is safe.
- DOM XSS helpers in `xss/dom_xss.py` are experimental and not part of the core pipeline.
