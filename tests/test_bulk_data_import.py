"""
Unit tests for bulk CSV/JSON certificate import parser.

These tests run without Django/NetBox — they only test the parsing logic.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

# Mock netbox/django modules for local testing without NetBox
_project_root = Path(__file__).parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

for mod in ("netbox", "netbox.plugins", "netbox.models", "django", "django.conf",
            "django.utils", "django.utils.timezone", "django.db", "django.db.models",
            "django.contrib.postgres.fields", "django.contrib.postgres.indexes",
            "django.urls", "utilities.choices"):
    if mod not in sys.modules:
        sys.modules[mod] = MagicMock()

# Patch timezone.make_aware to return the datetime as-is for testing
sys.modules["django.utils.timezone"].make_aware = lambda dt: dt

from netbox_ssl.utils.bulk_parser import (
    detect_format,
    parse,
    parse_csv,
    parse_json,
)

# ─── Format Detection ────────────────────────────────────────────────

class TestDetectFormat:
    def test_json_array(self):
        assert detect_format('[{"common_name": "example.com"}]') == "json"

    def test_json_object(self):
        assert detect_format('{"common_name": "example.com"}') == "json"

    def test_csv(self):
        assert detect_format("common_name,serial_number\nexample.com,01:AB") == "csv"

    def test_whitespace_json(self):
        assert detect_format('  \n[{"common_name": "x"}]') == "json"


# ─── Sample Data ─────────────────────────────────────────────────────

VALID_ROW = {
    "common_name": "example.com",
    "serial_number": "01:AB:CD:EF",
    "issuer": "DigiCert Inc",
    "valid_from": "2025-01-01",
    "valid_to": "2026-01-01",
    "fingerprint_sha256": "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
    "algorithm": "rsa",
    "key_size": "2048",
    "status": "active",
}

VALID_CSV_HEADER = "common_name,serial_number,issuer,valid_from,valid_to,fingerprint_sha256,algorithm,key_size,status,sans"
VALID_CSV_ROW = 'example.com,01:AB:CD:EF,DigiCert Inc,2025-01-01,2026-01-01,AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99,rsa,2048,active,www.example.com;api.example.com'


# ─── CSV Parsing ─────────────────────────────────────────────────────

class TestParseCSV:
    def test_valid_csv(self):
        csv_content = f"{VALID_CSV_HEADER}\n{VALID_CSV_ROW}"
        result = parse_csv(csv_content)
        assert not result.has_errors
        assert len(result.valid_rows) == 1
        row = result.valid_rows[0]
        assert row["common_name"] == "example.com"
        assert row["algorithm"] == "rsa"
        assert row["sans"] == ["www.example.com", "api.example.com"]

    def test_csv_bom(self):
        csv_content = f"\ufeff{VALID_CSV_HEADER}\n{VALID_CSV_ROW}"
        result = parse_csv(csv_content)
        assert not result.has_errors
        assert len(result.valid_rows) == 1

    def test_csv_missing_required_field(self):
        csv_content = "common_name,serial_number\nexample.com,01:AB"
        result = parse_csv(csv_content)
        assert result.has_errors
        assert any("issuer" in e.message for e in result.errors)

    def test_csv_invalid_algorithm(self):
        header = "common_name,serial_number,issuer,valid_from,valid_to,fingerprint_sha256,algorithm"
        row = "example.com,01:AB,DigiCert,2025-01-01,2026-01-01,AA:BB,invalid_algo"
        result = parse_csv(f"{header}\n{row}")
        assert result.has_errors
        assert any("algorithm" in e.field for e in result.errors)

    def test_csv_invalid_date(self):
        header = "common_name,serial_number,issuer,valid_from,valid_to,fingerprint_sha256,algorithm"
        row = "example.com,01:AB,DigiCert,not-a-date,2026-01-01,AA:BB,rsa"
        result = parse_csv(f"{header}\n{row}")
        assert result.has_errors
        assert any("valid_from" in e.field for e in result.errors)

    def test_csv_multiple_rows(self):
        row2 = 'test.com,02:CD:EF,LetsEncrypt,2025-06-01,2025-09-01,BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA,ecdsa,256,active,'
        csv_content = f"{VALID_CSV_HEADER}\n{VALID_CSV_ROW}\n{row2}"
        result = parse_csv(csv_content)
        assert not result.has_errors
        assert len(result.valid_rows) == 2

    def test_csv_empty_sans(self):
        header = "common_name,serial_number,issuer,valid_from,valid_to,fingerprint_sha256,algorithm,sans"
        row = "example.com,01:AB,DigiCert,2025-01-01,2026-01-01,AA:BB,rsa,"
        result = parse_csv(f"{header}\n{row}")
        assert not result.has_errors
        assert result.valid_rows[0]["sans"] == []

    def test_csv_optional_key_size(self):
        header = "common_name,serial_number,issuer,valid_from,valid_to,fingerprint_sha256,algorithm"
        row = "example.com,01:AB,DigiCert,2025-01-01,2026-01-01,AA:BB,rsa"
        result = parse_csv(f"{header}\n{row}")
        assert not result.has_errors
        assert "key_size" not in result.valid_rows[0]

    def test_csv_invalid_key_size(self):
        header = "common_name,serial_number,issuer,valid_from,valid_to,fingerprint_sha256,algorithm,key_size"
        row = "example.com,01:AB,DigiCert,2025-01-01,2026-01-01,AA:BB,rsa,not_a_number"
        result = parse_csv(f"{header}\n{row}")
        assert result.has_errors
        assert any("key_size" in e.field for e in result.errors)


# ─── JSON Parsing ────────────────────────────────────────────────────

class TestParseJSON:
    def test_valid_json_array(self):
        import json
        content = json.dumps([VALID_ROW])
        result = parse_json(content)
        assert not result.has_errors
        assert len(result.valid_rows) == 1
        assert result.valid_rows[0]["common_name"] == "example.com"

    def test_valid_json_single_object(self):
        import json
        content = json.dumps(VALID_ROW)
        result = parse_json(content)
        assert not result.has_errors
        assert len(result.valid_rows) == 1

    def test_json_with_list_sans(self):
        import json
        row = dict(VALID_ROW, sans=["www.example.com", "api.example.com"])
        content = json.dumps([row])
        result = parse_json(content)
        assert not result.has_errors
        assert result.valid_rows[0]["sans"] == ["www.example.com", "api.example.com"]

    def test_invalid_json(self):
        result = parse_json("{not valid json")
        assert result.has_errors
        assert any("Invalid JSON" in e.message for e in result.errors)

    def test_json_not_array_or_object(self):
        result = parse_json('"just a string"')
        assert result.has_errors

    def test_json_missing_required(self):
        import json
        content = json.dumps([{"common_name": "test.com"}])
        result = parse_json(content)
        assert result.has_errors

    def test_json_invalid_status(self):
        import json
        row = dict(VALID_ROW, status="invalid_status")
        content = json.dumps([row])
        result = parse_json(content)
        assert result.has_errors
        assert any("status" in e.field for e in result.errors)

    def test_json_tenant_ref(self):
        import json
        row = dict(VALID_ROW, tenant="My Tenant")
        content = json.dumps([row])
        result = parse_json(content)
        assert not result.has_errors
        assert result.valid_rows[0]["tenant_ref"] == "My Tenant"


# ─── Auto-detect Parse ───────────────────────────────────────────────

class TestParse:
    def test_auto_detect_csv(self):
        csv_content = f"{VALID_CSV_HEADER}\n{VALID_CSV_ROW}"
        result = parse(csv_content, fmt="auto")
        assert not result.has_errors
        assert len(result.valid_rows) == 1

    def test_auto_detect_json(self):
        import json
        result = parse(json.dumps([VALID_ROW]), fmt="auto")
        assert not result.has_errors
        assert len(result.valid_rows) == 1

    def test_explicit_format(self):
        import json
        result = parse(json.dumps([VALID_ROW]), fmt="json")
        assert not result.has_errors


# ─── Date Parsing ────────────────────────────────────────────────────

class TestDateParsing:
    def test_iso_date(self):
        import json
        row = dict(VALID_ROW, valid_from="2025-01-15", valid_to="2026-01-15")
        result = parse_json(json.dumps([row]))
        assert not result.has_errors
        assert result.valid_rows[0]["valid_from"].year == 2025

    def test_iso_datetime(self):
        import json
        row = dict(VALID_ROW, valid_from="2025-01-15T10:30:00", valid_to="2026-01-15T10:30:00")
        result = parse_json(json.dumps([row]))
        assert not result.has_errors

    def test_iso_datetime_with_tz(self):
        import json
        row = dict(VALID_ROW, valid_from="2025-01-15T10:30:00+00:00", valid_to="2026-01-15T10:30:00+00:00")
        result = parse_json(json.dumps([row]))
        assert not result.has_errors

    def test_datetime_with_space(self):
        import json
        row = dict(VALID_ROW, valid_from="2025-01-15 10:30:00", valid_to="2026-01-15 10:30:00")
        result = parse_json(json.dumps([row]))
        assert not result.has_errors
