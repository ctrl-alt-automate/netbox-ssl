"""
CSV parser for the URL Certificate Import feature (#106).

Parses a CSV (or pasted CSV text) of URLs-to-scrape into validated rows. This
layer is pure / DB-free and host-testable: it validates the *shape* of each row
(URL form, port, booleans) and normalizes host/port/SNI. Resolving
device/VM/service/tenant references against the database is the scan Script's
job (PR 2 view + script), since that needs DB access.

CSV schema (header row required):
    url               required   https://host[:port] or host:port (https assumed)
    assigned_device   optional   Device name or ID
    assigned_vm       optional   VM name or ID
    assigned_service  optional   Service name or device_id:service_name
    tenant            optional   Tenant name or slug
    verify_chain      optional   true/false (default true)
    sni               optional   SNI hostname override
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from urllib.parse import urlparse

# Aligned with the existing bulk-import caps (views/certificates.py).
MAX_ROWS = 500
URL_MAX_LENGTH = 2048
DEFAULT_PORT = 443

_TRUE = {"true", "yes", "1", "y", "t"}
_FALSE = {"false", "no", "0", "n", "f", ""}

KNOWN_COLUMNS = {
    "url",
    "assigned_device",
    "assigned_vm",
    "assigned_service",
    "tenant",
    "verify_chain",
    "sni",
}


@dataclass
class UrlRowError:
    """Validation error for a single CSV row."""

    row: int
    field: str
    message: str


@dataclass
class UrlImportRow:
    """A validated URL-import row (references unresolved — resolved in the Script)."""

    row: int
    url: str
    host: str
    port: int
    sni: str
    verify_chain: bool = True
    assigned_device: str = ""
    assigned_vm: str = ""
    assigned_service: str = ""
    tenant: str = ""


@dataclass
class UrlParseResult:
    """Result of parsing a URL-import CSV."""

    valid_rows: list[UrlImportRow] = field(default_factory=list)
    errors: list[UrlRowError] = field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        return len(self.errors) > 0


def _parse_bool(value: str, row: int, errors: list[UrlRowError]) -> bool:
    """Parse a verify_chain cell, defaulting to True; record an error on garbage."""
    cell = (value or "").strip().lower()
    if not cell:
        return True  # absent -> default verify
    if cell in _TRUE:
        return True
    if cell in _FALSE:
        return False
    errors.append(UrlRowError(row=row, field="verify_chain", message=f"Expected true/false, got {value!r}"))
    return True


def _normalize_url(raw: str, row: int, errors: list[UrlRowError]) -> tuple[str, str, int] | None:
    """Validate + normalize a url cell into (url, host, port).

    Accepts ``https://host[:port]`` or bare ``host[:port]`` (https assumed). Only
    the ``https`` scheme is accepted; the actual SSRF/IP checks happen later in
    the validator. Returns None (and records an error) on malformed input.
    """
    value = (raw or "").strip()
    if not value:
        errors.append(UrlRowError(row=row, field="url", message="url is required"))
        return None
    if len(value) > URL_MAX_LENGTH:
        errors.append(UrlRowError(row=row, field="url", message=f"url exceeds {URL_MAX_LENGTH} chars"))
        return None

    # Bare host[:port] → assume https so urlparse populates hostname/port.
    candidate = value if "://" in value else f"https://{value}"
    try:
        parsed = urlparse(candidate)
    except ValueError:
        errors.append(UrlRowError(row=row, field="url", message=f"Malformed URL: {value!r}"))
        return None

    if parsed.scheme != "https":
        errors.append(UrlRowError(row=row, field="url", message=f"Only https is supported, got {parsed.scheme!r}"))
        return None

    host = parsed.hostname
    if not host:
        errors.append(UrlRowError(row=row, field="url", message=f"URL has no host: {value!r}"))
        return None

    try:
        port = parsed.port or DEFAULT_PORT
    except ValueError:
        errors.append(UrlRowError(row=row, field="url", message=f"Invalid port in {value!r}"))
        return None

    # Canonical url we record on the imported cert.
    canonical = f"https://{host}:{port}"
    return canonical, host, port


def parse_csv(content: str) -> UrlParseResult:
    """Parse URL-import CSV content into validated rows."""
    result = UrlParseResult()

    if content.startswith("﻿"):
        content = content[1:]

    try:
        reader = csv.DictReader(io.StringIO(content))
    except Exception as e:  # pragma: no cover - csv rarely raises here
        result.errors.append(UrlRowError(row=0, field="", message=f"Cannot parse CSV: {e}"))
        return result

    if reader.fieldnames is None or "url" not in {(f or "").strip().lower() for f in reader.fieldnames}:
        result.errors.append(UrlRowError(row=0, field="url", message="CSV must have a 'url' header column"))
        return result

    for idx, raw_row in enumerate(reader, start=1):
        # Normalize header casing/whitespace.
        row = {(k or "").strip().lower(): (v or "").strip() for k, v in raw_row.items() if k}

        normalized = _normalize_url(row.get("url", ""), idx, result.errors)
        if normalized is None:
            continue
        url, host, port = normalized

        verify_chain = _parse_bool(row.get("verify_chain", ""), idx, result.errors)
        sni = row.get("sni", "") or host

        result.valid_rows.append(
            UrlImportRow(
                row=idx,
                url=url,
                host=host,
                port=port,
                sni=sni,
                verify_chain=verify_chain,
                assigned_device=row.get("assigned_device", ""),
                assigned_vm=row.get("assigned_vm", ""),
                assigned_service=row.get("assigned_service", ""),
                tenant=row.get("tenant", ""),
            )
        )

    if len(result.valid_rows) > MAX_ROWS:
        result.errors.append(
            UrlRowError(
                row=0,
                field="",
                message=f"Too many rows ({len(result.valid_rows)}). Maximum is {MAX_ROWS}; split into batches.",
            )
        )
        result.valid_rows = result.valid_rows[:MAX_ROWS]

    return result


def parse(content: str) -> UrlParseResult:
    """Parse URL-import content (CSV only)."""
    return parse_csv(content)
