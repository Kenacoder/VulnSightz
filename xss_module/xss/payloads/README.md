# Curated XSS probe references

Educational patterns adapted from
[payload-box/xss-payload-list](https://github.com/payload-box/xss-payload-list)
for authorized lab testing.

The scanner does **not** load the upstream All-In-One / WAF / Blind lists.
Runtime probes live in `xss/payload_catalog.py` and stay:

- context-mapped
- opt-in (`--extended-probes`)
- budget-limited
- free of external callbacks and data-exfiltration demos

See `docs/XSS_MODULE.md` for usage.
