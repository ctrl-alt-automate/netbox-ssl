"""
Unit tests for the URL-import CSV parser (#106, PR 2).

Pure / DB-free — host-runnable on the unit lane (`-m unit -p no:django`).
"""

import importlib.util
import sys

import pytest

# Mock the absent NetBox packages so importing netbox_ssl.utils.* (which triggers
# netbox_ssl/__init__.py -> from netbox.plugins import PluginConfig) works
# host-side. Django stays real. Same pattern as test_parser.py (issue #116).
try:
    _spec = importlib.util.find_spec("netbox")
    _NETBOX_AVAILABLE = _spec is not None and _spec.origin is not None
except (ValueError, ModuleNotFoundError):
    _NETBOX_AVAILABLE = False

if not _NETBOX_AVAILABLE and "netbox" not in sys.modules:
    from unittest.mock import MagicMock

    sys.modules["netbox"] = MagicMock()
    sys.modules["netbox.plugins"] = MagicMock()

from netbox_ssl.utils.url_bulk_parser import (  # noqa: E402
    DEFAULT_PORT,
    MAX_ROWS,
    UrlImportRow,
    parse,
)

pytestmark = pytest.mark.unit


def test_minimal_row_with_scheme():
    result = parse("url\nhttps://web.example.com:8443\n")
    assert not result.errors
    assert len(result.valid_rows) == 1
    row = result.valid_rows[0]
    assert isinstance(row, UrlImportRow)
    assert row.host == "web.example.com"
    assert row.port == 8443
    assert row.url == "https://web.example.com:8443"
    assert row.sni == "web.example.com"
    assert row.verify_chain is True


def test_bare_host_assumes_https_and_default_port():
    result = parse("url\nweb.example.com\n")
    assert not result.errors
    row = result.valid_rows[0]
    assert row.host == "web.example.com"
    assert row.port == DEFAULT_PORT
    assert row.url == "https://web.example.com:443"


def test_http_scheme_rejected():
    result = parse("url\nhttp://web.example.com\n")
    assert not result.valid_rows
    assert any(e.field == "url" and "https" in e.message for e in result.errors)


def test_all_optional_columns_captured():
    csv = (
        "url,assigned_device,assigned_vm,assigned_service,tenant,verify_chain,sni\n"
        "https://h.example.com:9443,dev01,vm02,svc:web,acme,false,sni.example.com\n"
    )
    result = parse(csv)
    assert not result.errors
    row = result.valid_rows[0]
    assert row.assigned_device == "dev01"
    assert row.assigned_vm == "vm02"
    assert row.assigned_service == "svc:web"
    assert row.tenant == "acme"
    assert row.verify_chain is False
    assert row.sni == "sni.example.com"


def test_verify_chain_default_true_when_absent():
    result = parse("url,tenant\nhttps://h.example.com,acme\n")
    assert result.valid_rows[0].verify_chain is True


def test_verify_chain_garbage_records_error_and_defaults_true():
    result = parse("url,verify_chain\nhttps://h.example.com,maybe\n")
    assert any(e.field == "verify_chain" for e in result.errors)
    assert result.valid_rows[0].verify_chain is True


def test_missing_url_column_is_fatal():
    result = parse("host,port\nweb.example.com,443\n")
    assert not result.valid_rows
    assert any(e.field == "url" for e in result.errors)


def test_blank_line_skipped_other_rows_survive():
    """csv.DictReader skips wholly-blank lines; valid rows still parse."""
    result = parse("url\n\nhttps://ok.example.com\n")
    assert len(result.valid_rows) == 1
    assert result.valid_rows[0].host == "ok.example.com"


def test_empty_url_cell_in_multi_column_row_errors():
    """A row present but with an empty url cell is a row-level error."""
    result = parse("url,tenant\n,acme\nhttps://ok.example.com,acme\n")
    assert len(result.valid_rows) == 1
    assert result.valid_rows[0].host == "ok.example.com"
    assert any(e.field == "url" for e in result.errors)


def test_oversized_url_rejected():
    long_host = "a" * 2100 + ".example.com"
    result = parse(f"url\nhttps://{long_host}\n")
    assert not result.valid_rows
    assert any("exceeds" in e.message for e in result.errors)


def test_header_casing_and_whitespace_normalized():
    result = parse(" URL , Tenant \nhttps://h.example.com, acme \n")
    assert not result.errors
    row = result.valid_rows[0]
    assert row.host == "h.example.com"
    assert row.tenant == "acme"


def test_row_cap_enforced():
    rows = "\n".join(f"https://h{i}.example.com" for i in range(MAX_ROWS + 10))
    result = parse("url\n" + rows + "\n")
    assert len(result.valid_rows) == MAX_ROWS
    assert any("Maximum is" in e.message for e in result.errors)
