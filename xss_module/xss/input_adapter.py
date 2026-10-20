"""Load and normalize crawl_map.json into deduplicated input points."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

from xss.crawl_map_schema import validate_crawl_map

logger = logging.getLogger("web_vuln.xss.input")


@dataclass(frozen=True)
class InputPoint:
    url: str
    method: str
    parameter: str
    input_type: str
    source: str  # query | form | endpoint
    original_value: str = ""
    enctype: str = "application/x-www-form-urlencoded"
    form_fields: tuple[tuple[str, str], ...] = ()
    renders_to: tuple[str, ...] = ()
    source_page: str = ""
    meta: dict[str, Any] = field(default_factory=dict, hash=False, compare=False)

    @property
    def key(self) -> tuple[str, str, str, str]:
        base = self.url.split("?", 1)[0]
        return (base, self.method.upper(), self.parameter, self.source)


def _strip_fragment(url: str) -> str:
    parts = urlparse(url)
    return urlunparse((parts.scheme, parts.netloc, parts.path, parts.params, parts.query, ""))


def _base_url(url: str) -> str:
    parts = urlparse(url)
    return urlunparse((parts.scheme, parts.netloc, parts.path, "", "", ""))


class InputAdapter:
    """Normalize crawl_map structures into InputPoint instances."""

    SKIP_FIELD_TYPES = {"submit", "button", "image", "file", "reset"}

    def load_path(self, path: str | Path) -> dict[str, Any]:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        errors = validate_crawl_map(data)
        if errors:
            raise ValueError("invalid crawl_map.json: " + "; ".join(errors))
        return data

    def load_data(self, data: dict[str, Any]) -> dict[str, Any]:
        errors = validate_crawl_map(data)
        if errors:
            raise ValueError("invalid crawl_map: " + "; ".join(errors))
        return data

    def extract_input_points(self, crawl_map: dict[str, Any]) -> list[InputPoint]:
        points: list[InputPoint] = []
        points.extend(self._from_pages(crawl_map.get("pages") or []))
        points.extend(self._from_forms(crawl_map.get("forms") or []))
        points.extend(self._from_endpoints(crawl_map.get("endpoints") or []))
        return self.deduplicate(points)

    def _from_pages(self, pages: list[dict[str, Any]]) -> list[InputPoint]:
        out: list[InputPoint] = []
        for page in pages:
            url = _strip_fragment(page.get("url", ""))
            method = (page.get("method") or "GET").upper()
            for param in page.get("params") or []:
                name = param.get("name")
                if not name:
                    continue
                source = param.get("source") or "query"
                out.append(
                    InputPoint(
                        url=_base_url(url) if source == "query" else url,
                        method=method if source != "query" else "GET",
                        parameter=name,
                        input_type=param.get("input_type") or "text",
                        source=source,
                        original_value=str(param.get("value") or ""),
                        renders_to=tuple(page.get("renders_from") or ()),
                    )
                )
        return out

    def _from_forms(self, forms: list[dict[str, Any]]) -> list[InputPoint]:
        out: list[InputPoint] = []
        for form in forms:
            action = _strip_fragment(form.get("action", ""))
            method = (form.get("method") or "POST").upper()
            enctype = (
                form.get("enctype") or "application/x-www-form-urlencoded"
            ).lower()
            if enctype not in {
                "application/x-www-form-urlencoded",
                "multipart/form-data",
                "text/plain",
            }:
                logger.debug("skipping unsupported enctype %s for %s", enctype, action)
                continue
            # Prefer urlencoded for testing; multipart still accepted as fields dict.
            fields = form.get("fields") or []
            field_pairs = tuple(
                (f.get("name", ""), str(f.get("value") or ""))
                for f in fields
                if f.get("name")
            )
            renders = tuple(form.get("renders_to") or ())
            source_page = form.get("source_page") or ""
            for f in fields:
                name = f.get("name")
                if not name:
                    continue
                itype = (f.get("input_type") or "text").lower()
                if itype in self.SKIP_FIELD_TYPES:
                    continue
                out.append(
                    InputPoint(
                        url=_base_url(action),
                        method=method,
                        parameter=name,
                        input_type=itype,
                        source="form",
                        original_value=str(f.get("value") or ""),
                        enctype="application/x-www-form-urlencoded",
                        form_fields=field_pairs,
                        renders_to=renders,
                        source_page=source_page,
                    )
                )
        return out

    def _from_endpoints(self, endpoints: list[dict[str, Any]]) -> list[InputPoint]:
        out: list[InputPoint] = []
        for ep in endpoints:
            url = _base_url(_strip_fragment(ep.get("url", "")))
            method = (ep.get("method") or "GET").upper()
            enctype = (
                ep.get("enctype") or "application/x-www-form-urlencoded"
            ).lower()
            renders = tuple(ep.get("renders_to") or ())
            source_page = ep.get("source_page") or ""
            params = ep.get("params") or []
            field_pairs = tuple(
                (p.get("name", ""), str(p.get("value") or ""))
                for p in params
                if p.get("name")
            )
            for param in params:
                name = param.get("name")
                if not name:
                    continue
                source = param.get("source") or (
                    "form" if method == "POST" else "query"
                )
                itype = (param.get("input_type") or "text").lower()
                if itype in self.SKIP_FIELD_TYPES:
                    continue
                out.append(
                    InputPoint(
                        url=url,
                        method=method,
                        parameter=name,
                        input_type=itype,
                        source=source,
                        original_value=str(param.get("value") or ""),
                        enctype=enctype
                        if source == "form"
                        else "application/x-www-form-urlencoded",
                        form_fields=field_pairs if source == "form" else (),
                        renders_to=renders,
                        source_page=source_page,
                    )
                )
        return out

    def deduplicate(self, points: list[InputPoint]) -> list[InputPoint]:
        seen: set[tuple[str, str, str, str]] = set()
        unique: list[InputPoint] = []
        for point in points:
            if point.key in seen:
                continue
            seen.add(point.key)
            unique.append(point)
        logger.info("normalized %d unique input points", len(unique))
        return unique
