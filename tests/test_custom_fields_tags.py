"""
Unit tests for custom fields and tag-based compliance filtering.

Tests tag_filter on CompliancePolicy and custom_fields export.
"""

import csv
import importlib.util
import io
import json
import sys
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Mock Django/NetBox before importing plugin code
# ---------------------------------------------------------------------------
try:
    _spec = importlib.util.find_spec("netbox")
    _NETBOX_AVAILABLE = _spec is not None and _spec.origin is not None
except (ValueError, ModuleNotFoundError):
    _NETBOX_AVAILABLE = False

if not _NETBOX_AVAILABLE and "netbox" not in sys.modules:
    for mod in [
        "django",
        "django.conf",
        "django.db",
        "django.db.models",
        "django.db.models.functions",
        "django.utils",
        "django.utils.timezone",
        "django.utils.translation",
        "django.contrib",
        "django.contrib.contenttypes",
        "django.contrib.contenttypes.fields",
        "django.contrib.contenttypes.models",
        "django.contrib.postgres",
        "django.contrib.postgres.fields",
        "django.contrib.postgres.indexes",
        "django.core",
        "django.core.exceptions",
        "django.urls",
        "django.views",
        "django.views.generic",
        "django.http",
        "netbox",
        "netbox.models",
        "netbox.plugins",
        "utilities",
        "utilities.choices",
    ]:
        if mod not in sys.modules:
            sys.modules[mod] = MagicMock()

from netbox_ssl.utils.compliance_checker import CheckResult, ComplianceChecker
from netbox_ssl.utils.export import CertificateExporter

# Mark all tests in this module as unit tests
pytestmark = pytest.mark.unit


class MockTag:
    """Mock tag for testing."""

    def __init__(self, pk: int, name: str):
        self.pk = pk
        self.name = name


class MockM2MManager:
    """Mock M2M manager that supports values_list and all."""

    def __init__(self, items: list):
        self._items = items

    def values_list(self, field: str, flat: bool = False):
        if field == "pk":
            return [item.pk for item in self._items]
        return [getattr(item, field) for item in self._items]

    def count(self):
        return len(self._items)

    def all(self):
        return self._items


class MockCertificate:
    """Mock certificate for compliance and export testing."""

    def __init__(self, common_name: str = "example.com", tags: list | None = None, **kwargs):
        self.common_name = common_name
        self.serial_number = kwargs.get("serial_number", "01:23:45")
        self.fingerprint_sha256 = kwargs.get("fingerprint_sha256", "AA:BB:CC")
        self.issuer = kwargs.get("issuer", "CN=Test CA")
        self.valid_from = kwargs.get("valid_from", datetime(2024, 1, 1))
        self.valid_to = kwargs.get("valid_to", datetime(2025, 1, 1))
        self.algorithm = kwargs.get("algorithm", "rsa")
        self.key_size = kwargs.get("key_size", 4096)
        self.status = kwargs.get("status", "active")
        self.tenant = kwargs.get("tenant")
        self.sans = kwargs.get("sans", ["example.com"])
        self.pem_content = kwargs.get("pem_content", "")
        self.issuer_chain = kwargs.get("issuer_chain", "")
        self.created = kwargs.get("created", datetime(2024, 1, 1, 12, 0, 0))
        self.last_updated = kwargs.get("last_updated", datetime(2024, 1, 15, 12, 0, 0))
        self.private_key_location = ""
        self.custom_field_data = kwargs.get("custom_field_data", {})

        self.tags = MockM2MManager(tags or [])
        self.assignments = MagicMock()
        self.assignments.count.return_value = 0
        self.assignments.all.return_value = []

    @property
    def days_remaining(self):
        if self.valid_to:
            return (self.valid_to - datetime.now()).days
        return None

    @property
    def is_expired(self):
        return self.valid_to and self.valid_to < datetime.now()

    @property
    def is_expiring_soon(self):
        days = self.days_remaining
        return days is not None and 0 < days <= 30

    @property
    def expiry_status(self):
        if self.is_expired:
            return "expired"
        if self.is_expiring_soon:
            return "warning"
        return "ok"


class MockPolicy:
    """Mock compliance policy with tag_filter."""

    def __init__(
        self,
        name: str = "Test Policy",
        policy_type: str = "min_key_size",
        parameters: dict | None = None,
        tag_filter_tags: list | None = None,
        enabled: bool = True,
    ):
        self.name = name
        self.policy_type = policy_type
        self.parameters = parameters or {"min_bits": 2048}
        self.enabled = enabled
        self.tag_filter = MockM2MManager(tag_filter_tags or [])


# ─────────────────────────────────────────────
# Tag-based compliance filtering tests
# ─────────────────────────────────────────────

# We patch check_certificate to return a simple CheckResult, avoiding
# the model imports that check_certificate triggers internally.
_MOCK_PASS = CheckResult(passed=True, message="OK", checked_value="4096 bits", expected_value=">= 2048 bits")


class TestTagBasedComplianceFiltering:
    """Test that run_all_checks respects tag_filter on policies."""

    @patch.object(ComplianceChecker, "check_certificate", return_value=_MOCK_PASS)
    def test_policy_without_tags_applies_to_all(self, mock_check):
        """Policy with empty tag_filter applies to every certificate."""
        cert = MockCertificate(key_size=4096)
        policy = MockPolicy(tag_filter_tags=[])

        results = ComplianceChecker.run_all_checks(cert, policies=[policy])
        assert len(results) == 1
        assert results[0][1].passed is True
        mock_check.assert_called_once_with(cert, policy)

    @patch.object(ComplianceChecker, "check_certificate", return_value=_MOCK_PASS)
    def test_policy_with_matching_tags_applies(self, mock_check):
        """Policy with tag_filter applies when certificate has ALL required tags."""
        tag_prod = MockTag(pk=1, name="production")
        tag_ext = MockTag(pk=2, name="external")

        cert = MockCertificate(key_size=4096, tags=[tag_prod, tag_ext])
        policy = MockPolicy(tag_filter_tags=[tag_prod])

        results = ComplianceChecker.run_all_checks(cert, policies=[policy])
        assert len(results) == 1
        mock_check.assert_called_once()

    @patch.object(ComplianceChecker, "check_certificate", return_value=_MOCK_PASS)
    def test_policy_with_all_required_tags_applies(self, mock_check):
        """Policy applies when certificate has ALL of its required tags."""
        tag_prod = MockTag(pk=1, name="production")
        tag_ext = MockTag(pk=2, name="external")

        cert = MockCertificate(key_size=4096, tags=[tag_prod, tag_ext])
        policy = MockPolicy(tag_filter_tags=[tag_prod, tag_ext])

        results = ComplianceChecker.run_all_checks(cert, policies=[policy])
        assert len(results) == 1

    @patch.object(ComplianceChecker, "check_certificate", return_value=_MOCK_PASS)
    def test_policy_skipped_when_cert_lacks_required_tags(self, mock_check):
        """Policy is skipped when certificate doesn't have all required tags."""
        tag_prod = MockTag(pk=1, name="production")
        tag_ext = MockTag(pk=2, name="external")

        cert = MockCertificate(key_size=4096, tags=[tag_prod])
        policy = MockPolicy(tag_filter_tags=[tag_prod, tag_ext])

        results = ComplianceChecker.run_all_checks(cert, policies=[policy])
        assert len(results) == 0
        mock_check.assert_not_called()

    @patch.object(ComplianceChecker, "check_certificate", return_value=_MOCK_PASS)
    def test_policy_skipped_when_cert_has_no_tags(self, mock_check):
        """Policy with tags is skipped for certificate without any tags."""
        tag_prod = MockTag(pk=1, name="production")

        cert = MockCertificate(key_size=4096, tags=[])
        policy = MockPolicy(tag_filter_tags=[tag_prod])

        results = ComplianceChecker.run_all_checks(cert, policies=[policy])
        assert len(results) == 0
        mock_check.assert_not_called()

    @patch.object(ComplianceChecker, "check_certificate", return_value=_MOCK_PASS)
    def test_mixed_policies_some_filtered(self, mock_check):
        """Mix of tagged and untagged policies: only matching ones apply."""
        tag_prod = MockTag(pk=1, name="production")
        tag_staging = MockTag(pk=3, name="staging")

        cert = MockCertificate(key_size=4096, tags=[tag_prod])

        global_policy = MockPolicy(name="Global", tag_filter_tags=[])
        prod_policy = MockPolicy(name="Production", tag_filter_tags=[tag_prod])
        staging_policy = MockPolicy(name="Staging", tag_filter_tags=[tag_staging])

        results = ComplianceChecker.run_all_checks(cert, policies=[global_policy, prod_policy, staging_policy])
        assert len(results) == 2
        policy_names = [r[0].name for r in results]
        assert "Global" in policy_names
        assert "Production" in policy_names
        assert "Staging" not in policy_names
        # check_certificate should have been called twice (Global + Production)
        assert mock_check.call_count == 2

    @patch.object(ComplianceChecker, "check_certificate", return_value=_MOCK_PASS)
    def test_cert_with_superset_of_required_tags(self, mock_check):
        """Certificate with more tags than required still matches."""
        tag_a = MockTag(pk=1, name="a")
        tag_b = MockTag(pk=2, name="b")
        tag_c = MockTag(pk=3, name="c")

        cert = MockCertificate(tags=[tag_a, tag_b, tag_c])
        policy = MockPolicy(tag_filter_tags=[tag_a, tag_b])

        results = ComplianceChecker.run_all_checks(cert, policies=[policy])
        assert len(results) == 1


# ─────────────────────────────────────────────
# Custom fields export tests
# ─────────────────────────────────────────────


class TestCustomFieldExportJSON:
    """Test custom_fields in JSON exports."""

    def test_custom_fields_included(self):
        """Custom field data is included in JSON export."""
        cert = MockCertificate(
            custom_field_data={"environment": "production", "team": "platform"},
        )
        result = CertificateExporter.export_to_json([cert], fields=CertificateExporter.EXTENDED_FIELDS)
        data = json.loads(result)
        assert data[0]["custom_fields"] == {"environment": "production", "team": "platform"}

    def test_custom_fields_empty_dict_when_none(self):
        """Custom fields default to empty dict when no data."""
        cert = MockCertificate(custom_field_data=None)
        result = CertificateExporter.export_to_json([cert], fields=["common_name", "custom_fields"])
        data = json.loads(result)
        assert data[0]["custom_fields"] == {}

    def test_custom_fields_not_in_default_fields(self):
        """Default fields export does not include custom_fields."""
        cert = MockCertificate(custom_field_data={"environment": "production"})
        result = CertificateExporter.export_to_json([cert], fields=CertificateExporter.DEFAULT_FIELDS)
        data = json.loads(result)
        assert "custom_fields" not in data[0]

    def test_custom_fields_with_various_types(self):
        """Custom fields support different value types."""
        cert = MockCertificate(
            custom_field_data={"count": 42, "active": True, "label": "test"},
        )
        result = CertificateExporter.export_to_json([cert], fields=["common_name", "custom_fields"])
        data = json.loads(result)
        assert data[0]["custom_fields"]["count"] == 42
        assert data[0]["custom_fields"]["active"] is True


class TestCustomFieldExportCSV:
    """Test custom_fields flattening in CSV exports."""

    def test_custom_fields_flattened_with_prefix(self):
        """Custom fields appear as cf_ prefixed columns in CSV."""
        cert = MockCertificate(
            custom_field_data={"environment": "production", "team": "platform"},
        )
        result = CertificateExporter.export_to_csv([cert], fields=["common_name", "custom_fields"])
        reader = csv.DictReader(io.StringIO(result))
        rows = list(reader)
        assert len(rows) == 1
        assert rows[0]["cf_environment"] == "production"
        assert rows[0]["cf_team"] == "platform"
        assert rows[0]["common_name"] == "example.com"

    def test_csv_consistent_columns_across_certs(self):
        """All CSV rows have same custom field columns even if values differ."""
        cert1 = MockCertificate(
            common_name="cert1.com",
            custom_field_data={"environment": "production"},
        )
        cert2 = MockCertificate(
            common_name="cert2.com",
            custom_field_data={"environment": "staging", "team": "infra"},
        )
        result = CertificateExporter.export_to_csv([cert1, cert2], fields=["common_name", "custom_fields"])
        reader = csv.DictReader(io.StringIO(result))
        rows = list(reader)
        assert len(rows) == 2
        # Both rows have both cf_ columns
        assert "cf_environment" in rows[0]
        assert "cf_team" in rows[0]
        assert rows[0]["cf_team"] == ""  # cert1 has no team
        assert rows[1]["cf_team"] == "infra"

    def test_csv_no_cf_columns_without_custom_fields_in_fields(self):
        """No cf_ columns when custom_fields not in requested fields."""
        cert = MockCertificate(custom_field_data={"environment": "production"})
        result = CertificateExporter.export_to_csv([cert], fields=["common_name", "status"])
        reader = csv.DictReader(io.StringIO(result))
        rows = list(reader)
        assert "cf_environment" not in rows[0]

    def test_csv_empty_custom_fields_no_cf_columns(self):
        """No cf_ columns when all certs have empty custom field data."""
        cert = MockCertificate(custom_field_data={})
        result = CertificateExporter.export_to_csv([cert], fields=["common_name", "custom_fields"])
        header = result.split("\n")[0]
        assert "cf_" not in header


class TestCustomFieldExportAllowlist:
    """Test that custom_fields is properly in the allowlist."""

    def test_custom_fields_in_extended_fields(self):
        assert "custom_fields" in CertificateExporter.EXTENDED_FIELDS

    def test_custom_fields_in_allowed_fields(self):
        assert "custom_fields" in CertificateExporter.ALLOWED_FIELDS

    def test_custom_fields_not_in_default_fields(self):
        assert "custom_fields" not in CertificateExporter.DEFAULT_FIELDS
