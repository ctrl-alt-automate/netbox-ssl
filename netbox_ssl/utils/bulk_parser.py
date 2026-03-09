"""
Bulk CSV/JSON parser for certificate metadata import.

Parses CSV and JSON content into validated certificate dicts ready for creation.
"""

import csv
import io
import json
from dataclasses import dataclass, field
from datetime import datetime

from django.utils import timezone

REQUIRED_FIELDS = {
    "common_name",
    "serial_number",
    "issuer",
    "valid_from",
    "valid_to",
    "fingerprint_sha256",
    "algorithm",
}
VALID_STATUSES = {"active", "expired", "replaced", "revoked", "pending"}
VALID_ALGORITHMS = {"rsa", "ecdsa", "ed25519", "unknown"}
DATE_FORMATS = ["%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"]


@dataclass
class RowError:
    """Validation error for a single row."""

    row: int
    field: str
    message: str


@dataclass
class BulkParseResult:
    """Result of bulk parsing."""

    valid_rows: list[dict] = field(default_factory=list)
    errors: list[RowError] = field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        return len(self.errors) > 0


def detect_format(content: str) -> str:
    """Auto-detect if content is CSV or JSON."""
    stripped = content.strip()
    if stripped.startswith("[") or stripped.startswith("{"):
        return "json"
    return "csv"


def _parse_date(value: str) -> datetime | None:
    """Parse a date string trying multiple formats."""
    for fmt in DATE_FORMATS:
        try:
            dt = datetime.strptime(value.strip(), fmt)
            if dt.tzinfo is None:
                dt = timezone.make_aware(dt)
            return dt
        except ValueError:
            continue
    return None


def _validate_row(data: dict, row_index: int) -> tuple[dict, list[RowError]]:
    """Validate and normalize a single row of certificate data."""
    errors = []
    cleaned = {}

    # Check required fields
    for f in REQUIRED_FIELDS:
        val = data.get(f, "").strip() if isinstance(data.get(f), str) else data.get(f)
        if not val:
            errors.append(RowError(row=row_index, field=f, message=f"Required field '{f}' is missing or empty"))

    if errors:
        return cleaned, errors

    # Common name
    cleaned["common_name"] = data["common_name"].strip()

    # Serial number
    cleaned["serial_number"] = data["serial_number"].strip()

    # Fingerprint
    cleaned["fingerprint_sha256"] = data["fingerprint_sha256"].strip()

    # Issuer
    cleaned["issuer"] = data["issuer"].strip()

    # Algorithm
    algo = data["algorithm"].strip().lower()
    if algo not in VALID_ALGORITHMS:
        errors.append(
            RowError(
                row=row_index,
                field="algorithm",
                message=f"Invalid algorithm '{algo}'. Must be one of: {', '.join(sorted(VALID_ALGORITHMS))}",
            )
        )
    else:
        cleaned["algorithm"] = algo

    # Status
    status = data.get("status", "active").strip().lower()
    if status not in VALID_STATUSES:
        errors.append(
            RowError(
                row=row_index,
                field="status",
                message=f"Invalid status '{status}'. Must be one of: {', '.join(sorted(VALID_STATUSES))}",
            )
        )
    else:
        cleaned["status"] = status

    # Dates
    for date_field in ("valid_from", "valid_to"):
        raw = data[date_field].strip() if isinstance(data[date_field], str) else str(data[date_field])
        parsed = _parse_date(raw)
        if parsed is None:
            errors.append(
                RowError(
                    row=row_index,
                    field=date_field,
                    message=f"Cannot parse date '{raw}'. Use ISO 8601 format (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)",
                )
            )
        else:
            cleaned[date_field] = parsed

    # Key size (optional)
    key_size = data.get("key_size", "")
    if key_size:
        try:
            cleaned["key_size"] = int(key_size)
        except (ValueError, TypeError):
            errors.append(
                RowError(row=row_index, field="key_size", message=f"Invalid key_size '{key_size}' — must be integer")
            )

    # SANs (optional, semicolon-separated in CSV, list in JSON)
    sans = data.get("sans", "")
    if isinstance(sans, list):
        cleaned["sans"] = sans
    elif isinstance(sans, str) and sans.strip():
        cleaned["sans"] = [s.strip() for s in sans.split(";") if s.strip()]
    else:
        cleaned["sans"] = []

    # Optional string fields
    for opt_field in ("private_key_location", "issuer_chain", "pem_content"):
        val = data.get(opt_field, "")
        if val:
            cleaned[opt_field] = val.strip() if isinstance(val, str) else str(val)

    # Tenant (by name or ID — resolved later)
    tenant_val = data.get("tenant", "")
    if tenant_val:
        cleaned["tenant_ref"] = str(tenant_val).strip()

    return cleaned, errors


def parse_csv(content: str) -> BulkParseResult:
    """Parse CSV content into validated certificate dicts."""
    result = BulkParseResult()

    # Strip BOM
    if content.startswith("\ufeff"):
        content = content[1:]

    try:
        reader = csv.DictReader(io.StringIO(content))
    except Exception as e:
        result.errors.append(RowError(row=0, field="", message=f"Cannot parse CSV: {e}"))
        return result

    for idx, row in enumerate(reader, start=1):
        cleaned, errors = _validate_row(row, idx)
        if errors:
            result.errors.extend(errors)
        else:
            result.valid_rows.append(cleaned)

    return result


def parse_json(content: str) -> BulkParseResult:
    """Parse JSON content into validated certificate dicts."""
    result = BulkParseResult()

    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        result.errors.append(RowError(row=0, field="", message=f"Invalid JSON: {e}"))
        return result

    if isinstance(data, dict):
        data = [data]

    if not isinstance(data, list):
        result.errors.append(RowError(row=0, field="", message="JSON must be an array of certificate objects"))
        return result

    for idx, item in enumerate(data, start=1):
        if not isinstance(item, dict):
            result.errors.append(RowError(row=idx, field="", message="Each item must be a JSON object"))
            continue
        cleaned, errors = _validate_row(item, idx)
        if errors:
            result.errors.extend(errors)
        else:
            result.valid_rows.append(cleaned)

    return result


def parse(content: str, fmt: str = "auto") -> BulkParseResult:
    """Parse content in the specified format (csv, json, or auto-detect)."""
    if fmt == "auto":
        fmt = detect_format(content)

    if fmt == "json":
        return parse_json(content)
    return parse_csv(content)
