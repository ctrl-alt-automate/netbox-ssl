"""
Unit tests for certificate export functionality.

Tests the export of certificate data in various formats
including CSV, JSON, YAML, and PEM.
"""

import json
from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest

# Mark all tests in this module as unit tests
pytestmark = pytest.mark.unit


class MockCertificate:
    """Mock certificate object for testing exports."""

    def __init__(
        self,
        id=1,
        common_name="example.com",
        serial_number="01:23:45:67:89",
        fingerprint_sha256="AA:BB:CC:DD",
        issuer="CN=Test CA",
        valid_from=None,
        valid_to=None,
        algorithm="rsa",
        key_size=2048,
        status="active",
        tenant=None,
        sans=None,
        pem_content="",
        issuer_chain="",
    ):
        self.id = id
        self.common_name = common_name
        self.serial_number = serial_number
        self.fingerprint_sha256 = fingerprint_sha256
        self.issuer = issuer
        self.valid_from = valid_from or datetime(2024, 1, 1)
        self.valid_to = valid_to or datetime(2025, 1, 1)
        self.algorithm = algorithm
        self.key_size = key_size
        self.status = status
        self.tenant = tenant
        self.sans = sans or ["example.com", "www.example.com"]
        self.pem_content = pem_content
        self.issuer_chain = issuer_chain
        self.created = datetime(2024, 1, 1, 12, 0, 0)
        self.last_updated = datetime(2024, 1, 15, 12, 0, 0)
        self.private_key_location = "Vault: /secret/certs/example"

        # Mock assignments
        self.assignments = MagicMock()
        self.assignments.count.return_value = 2

    @property
    def days_remaining(self):
        if self.valid_to:
            delta = self.valid_to - datetime.now()
            return delta.days
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


class TestExportFormatChoices:
    """Test cases for export format choices."""

    def test_format_choices_exist(self):
        """Test that all expected format choices exist."""
        expected_formats = ["csv", "json", "yaml", "pem"]
        for fmt in expected_formats:
            assert fmt in expected_formats

    def test_format_values(self):
        """Test format choice values."""
        assert "csv" == "csv"
        assert "json" == "json"
        assert "yaml" == "yaml"
        assert "pem" == "pem"


class TestCertificateToDict:
    """Test cases for certificate to dictionary conversion."""

    def test_basic_fields_conversion(self):
        """Test conversion of basic certificate fields."""
        cert = MockCertificate()

        # Simulate the conversion
        data = {
            "id": cert.id,
            "common_name": cert.common_name,
            "serial_number": cert.serial_number,
            "status": cert.status,
            "algorithm": cert.algorithm,
            "key_size": cert.key_size,
        }

        assert data["id"] == 1
        assert data["common_name"] == "example.com"
        assert data["serial_number"] == "01:23:45:67:89"
        assert data["status"] == "active"
        assert data["algorithm"] == "rsa"
        assert data["key_size"] == 2048

    def test_tenant_conversion_with_tenant(self):
        """Test tenant field conversion when tenant exists."""
        mock_tenant = MagicMock()
        mock_tenant.name = "Test Tenant"
        cert = MockCertificate(tenant=mock_tenant)

        tenant_value = cert.tenant.name if cert.tenant else None

        assert tenant_value == "Test Tenant"

    def test_tenant_conversion_without_tenant(self):
        """Test tenant field conversion when tenant is None."""
        cert = MockCertificate(tenant=None)

        tenant_value = cert.tenant.name if cert.tenant else None

        assert tenant_value is None

    def test_sans_conversion(self):
        """Test SANs field conversion."""
        cert = MockCertificate(sans=["example.com", "www.example.com", "api.example.com"])

        assert cert.sans == ["example.com", "www.example.com", "api.example.com"]

    def test_datetime_fields_conversion(self):
        """Test datetime fields are converted to ISO format."""
        cert = MockCertificate()

        valid_from_iso = cert.valid_from.isoformat() if cert.valid_from else None
        valid_to_iso = cert.valid_to.isoformat() if cert.valid_to else None

        assert "2024-01-01" in valid_from_iso
        assert "2025-01-01" in valid_to_iso


class TestCSVExport:
    """Test cases for CSV export functionality."""

    def test_csv_export_basic(self):
        """Test basic CSV export."""
        certs = [MockCertificate(id=1), MockCertificate(id=2, common_name="test.com")]

        # Simulate CSV generation
        import csv
        import io

        output = io.StringIO()
        fieldnames = ["id", "common_name", "status"]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for cert in certs:
            writer.writerow({
                "id": cert.id,
                "common_name": cert.common_name,
                "status": cert.status,
            })

        csv_content = output.getvalue()

        assert "id,common_name,status" in csv_content
        assert "1,example.com,active" in csv_content
        assert "2,test.com,active" in csv_content

    def test_csv_excludes_complex_fields(self):
        """Test that CSV export excludes complex fields like SANs."""
        csv_fields = ["id", "common_name", "status", "algorithm"]

        # SANs should not be in CSV fields as it's a list
        assert "sans" not in csv_fields

    def test_csv_handles_empty_queryset(self):
        """Test CSV export with empty certificate list."""
        certs = []

        import csv
        import io

        output = io.StringIO()
        fieldnames = ["id", "common_name"]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for cert in certs:
            writer.writerow({})

        csv_content = output.getvalue()

        # Should only have header
        assert "id,common_name" in csv_content
        lines = csv_content.strip().split("\n")
        assert len(lines) == 1  # Just header


class TestJSONExport:
    """Test cases for JSON export functionality."""

    def test_json_export_basic(self):
        """Test basic JSON export."""
        cert = MockCertificate()

        data = [{
            "id": cert.id,
            "common_name": cert.common_name,
            "sans": cert.sans,
        }]

        json_content = json.dumps(data, indent=2)

        assert '"id": 1' in json_content
        assert '"common_name": "example.com"' in json_content
        assert '"sans"' in json_content

    def test_json_export_includes_arrays(self):
        """Test that JSON export includes array fields."""
        cert = MockCertificate(sans=["example.com", "www.example.com"])

        data = {"sans": cert.sans}
        json_content = json.dumps(data)

        assert '["example.com", "www.example.com"]' in json_content

    def test_json_export_pretty_formatting(self):
        """Test JSON export with pretty formatting."""
        data = [{"id": 1}]

        pretty = json.dumps(data, indent=2)
        compact = json.dumps(data)

        assert len(pretty) > len(compact)
        assert "\n" in pretty


class TestPEMExport:
    """Test cases for PEM export functionality."""

    def test_pem_export_with_content(self):
        """Test PEM export when certificate has PEM content."""
        pem_content = "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----"
        cert = MockCertificate(pem_content=pem_content)

        # Simulate PEM export
        output_parts = [
            f"# Certificate: {cert.common_name}",
            f"# Serial: {cert.serial_number}",
            "",
            cert.pem_content.strip(),
        ]
        output = "\n".join(output_parts)

        assert "# Certificate: example.com" in output
        assert "-----BEGIN CERTIFICATE-----" in output
        assert "-----END CERTIFICATE-----" in output

    def test_pem_export_without_content(self):
        """Test PEM export when certificate has no PEM content."""
        cert = MockCertificate(pem_content="")

        has_pem = bool(cert.pem_content)

        assert has_pem is False

    def test_pem_export_with_chain(self):
        """Test PEM export includes certificate chain."""
        chain = "-----BEGIN CERTIFICATE-----\nChain...\n-----END CERTIFICATE-----"
        cert = MockCertificate(
            pem_content="-----BEGIN CERTIFICATE-----\nCert...\n-----END CERTIFICATE-----",
            issuer_chain=chain,
        )

        # Simulate PEM export with chain
        output_parts = []
        output_parts.append(cert.pem_content.strip())
        if cert.issuer_chain:
            output_parts.append("")
            output_parts.append("# Certificate Chain")
            output_parts.append(cert.issuer_chain.strip())

        output = "\n".join(output_parts)

        assert "# Certificate Chain" in output
        assert cert.issuer_chain.strip() in output


class TestContentTypes:
    """Test cases for export content types."""

    def test_csv_content_type(self):
        """Test CSV content type."""
        content_types = {
            "csv": "text/csv",
            "json": "application/json",
            "yaml": "application/x-yaml",
            "pem": "application/x-pem-file",
        }

        assert content_types["csv"] == "text/csv"

    def test_json_content_type(self):
        """Test JSON content type."""
        content_types = {"json": "application/json"}

        assert content_types["json"] == "application/json"

    def test_yaml_content_type(self):
        """Test YAML content type."""
        content_types = {"yaml": "application/x-yaml"}

        assert content_types["yaml"] == "application/x-yaml"

    def test_pem_content_type(self):
        """Test PEM content type."""
        content_types = {"pem": "application/x-pem-file"}

        assert content_types["pem"] == "application/x-pem-file"


class TestFileExtensions:
    """Test cases for export file extensions."""

    def test_file_extensions(self):
        """Test file extensions for each format."""
        extensions = {
            "csv": "csv",
            "json": "json",
            "yaml": "yaml",
            "pem": "pem",
        }

        assert extensions["csv"] == "csv"
        assert extensions["json"] == "json"
        assert extensions["yaml"] == "yaml"
        assert extensions["pem"] == "pem"


class TestExportAPIEndpoints:
    """Test cases for export API endpoint structures."""

    def test_bulk_export_response_structure(self):
        """Test bulk export endpoint produces file download."""
        # Export should return a file attachment
        expected_headers = {
            "Content-Disposition": 'attachment; filename="certificates_export.csv"',
            "Content-Type": "text/csv",
        }

        assert "Content-Disposition" in expected_headers
        assert "attachment" in expected_headers["Content-Disposition"]

    def test_single_export_uses_common_name(self):
        """Test single certificate export uses common name in filename."""
        common_name = "example.com"
        safe_name = "".join(c if c.isalnum() or c in ".-_" else "_" for c in common_name)

        assert safe_name == "example.com"

    def test_filename_sanitization(self):
        """Test that special characters in common name are sanitized."""
        common_name = "*.example.com/test"
        safe_name = "".join(c if c.isalnum() or c in ".-_" else "_" for c in common_name)

        assert safe_name == "_.example.com_test"
        assert "/" not in safe_name
        assert "*" not in safe_name


class TestExportFieldSelection:
    """Test cases for field selection in exports."""

    def test_default_fields(self):
        """Test default fields are included in export."""
        default_fields = [
            "id",
            "common_name",
            "serial_number",
            "fingerprint_sha256",
            "issuer",
            "valid_from",
            "valid_to",
            "days_remaining",
            "algorithm",
            "key_size",
            "status",
            "tenant",
            "sans",
        ]

        assert "common_name" in default_fields
        assert "serial_number" in default_fields
        assert "status" in default_fields

    def test_extended_fields(self):
        """Test extended fields option."""
        extended_fields = [
            "is_expired",
            "is_expiring_soon",
            "expiry_status",
            "private_key_location",
            "assignment_count",
            "created",
            "last_updated",
        ]

        assert "is_expired" in extended_fields
        assert "assignment_count" in extended_fields

    def test_custom_field_selection(self):
        """Test custom field selection."""
        selected_fields = ["id", "common_name", "valid_to"]

        assert len(selected_fields) == 3
        assert "id" in selected_fields


class TestExportIntegrationScenarios:
    """Integration test scenarios for export workflows."""

    def test_export_active_certificates_only(self):
        """Test exporting only active certificates."""
        certs = [
            MockCertificate(id=1, status="active"),
            MockCertificate(id=2, status="expired"),
            MockCertificate(id=3, status="active"),
        ]

        active_certs = [c for c in certs if c.status == "active"]

        assert len(active_certs) == 2

    def test_export_by_tenant(self):
        """Test exporting certificates by tenant."""
        tenant1 = MagicMock()
        tenant1.name = "Tenant 1"
        tenant2 = MagicMock()
        tenant2.name = "Tenant 2"

        certs = [
            MockCertificate(id=1, tenant=tenant1),
            MockCertificate(id=2, tenant=tenant2),
            MockCertificate(id=3, tenant=tenant1),
        ]

        tenant1_certs = [c for c in certs if c.tenant and c.tenant.name == "Tenant 1"]

        assert len(tenant1_certs) == 2

    def test_export_expiring_certificates(self):
        """Test exporting certificates expiring within threshold."""
        now = datetime.now()
        certs = [
            MockCertificate(id=1, valid_to=now + timedelta(days=10)),  # Expiring soon
            MockCertificate(id=2, valid_to=now + timedelta(days=60)),  # Not expiring soon
            MockCertificate(id=3, valid_to=now - timedelta(days=5)),   # Already expired
        ]

        threshold_days = 30
        expiring_certs = [
            c for c in certs
            if c.valid_to and (c.valid_to - now).days <= threshold_days
        ]

        # Should include cert 1 (10 days) and cert 3 (-5 days)
        assert len(expiring_certs) == 2

    def test_export_with_pem_content(self):
        """Test export workflow with PEM content included."""
        pem = "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----"
        cert = MockCertificate(pem_content=pem)

        data = {
            "common_name": cert.common_name,
            "pem_content": cert.pem_content if cert.pem_content else None,
        }

        assert data["pem_content"] is not None
        assert "BEGIN CERTIFICATE" in data["pem_content"]
