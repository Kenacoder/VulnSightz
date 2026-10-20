# crawl_map.json Schema (v1.0)

Input contract consumed by the XSS module. Crawl maps are produced by an
**external Recon module** (not included in this package). XSS only validates and
reads this format.

## Top-level

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | string | yes | Schema version (`1.0`) |
| `target` | string | yes | Primary origin crawled |
| `generated_at` | string | no | ISO-8601 timestamp |
| `pages` | array | yes | Discovered pages |
| `forms` | array | no | Discovered HTML forms |
| `endpoints` | array | no | Normalized input endpoints |

## Page object

- `url` (string, required)
- `method` (string, default `GET`)
- `status` (number)
- `content_type` (string)
- `params` (array of `{name, value, source, input_type}`)
- `forms` (array of summaries)
- `links` (array of URLs)
- `renders_from` (array of URLs)

## Form object

- `action` (string, required)
- `method` (string)
- `enctype` (string)
- `fields` (array of `{name, value, input_type, required}`)
- `source_page` (string)
- `renders_to` (array of URLs) — used by stored XSS correlation

## Endpoint object

- `url`, `method`, `params`, optional `enctype`, `source_page`, `renders_to`

See `fixtures/sample_crawl_map.json` for a complete example.
