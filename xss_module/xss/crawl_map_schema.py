"""crawl_map.json validation for the XSS module input contract.

The XSS module consumes crawl maps produced by an external Recon module.
This file only validates/consumes that schema; it does not implement crawling.
"""

from __future__ import annotations

from typing import Any

CRAWL_MAP_VERSION = "1.0"

REQUIRED_TOP_LEVEL = {"version", "target", "pages"}


def validate_crawl_map(data: Any) -> list[str]:
    """Return a list of validation errors (empty means OK)."""
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["crawl_map root must be an object"]

    for key in REQUIRED_TOP_LEVEL:
        if key not in data:
            errors.append(f"missing required top-level field: {key}")

    if "pages" in data and not isinstance(data["pages"], list):
        errors.append("pages must be a list")
    if "forms" in data and data["forms"] is not None and not isinstance(data["forms"], list):
        errors.append("forms must be a list when present")
    if "endpoints" in data and data["endpoints"] is not None and not isinstance(
        data["endpoints"], list
    ):
        errors.append("endpoints must be a list when present")

    for i, page in enumerate(data.get("pages") or []):
        if not isinstance(page, dict):
            errors.append(f"pages[{i}] must be an object")
            continue
        if "url" not in page:
            errors.append(f"pages[{i}].url is required")
        if "method" in page and str(page["method"]).upper() not in {
            "GET",
            "POST",
            "PUT",
            "DELETE",
            "PATCH",
            "HEAD",
            "OPTIONS",
        }:
            errors.append(f"pages[{i}].method is invalid")

    for i, form in enumerate(data.get("forms") or []):
        if not isinstance(form, dict):
            errors.append(f"forms[{i}] must be an object")
            continue
        if "action" not in form:
            errors.append(f"forms[{i}].action is required")
        if "fields" in form and not isinstance(form["fields"], list):
            errors.append(f"forms[{i}].fields must be a list")

    return errors
