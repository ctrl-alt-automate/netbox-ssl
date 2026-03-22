from pathlib import Path

try:
    from conftest import get_plugin_source_dir
except ImportError:
    def get_plugin_source_dir():
        local = Path(__file__).parent.parent / "netbox_ssl"
        if local.is_dir(): return local
        docker = Path("/opt/netbox/netbox/netbox_ssl")
        if docker.is_dir(): return docker
        return local

"""
Unit tests for renewal reminders feature (#47).

Tests model fields, event payload enrichment, serializer computed field,
and migration existence without requiring a running NetBox instance.
"""

import importlib.util
import os
import sys
from datetime import datetime, timezone
from types import SimpleNamespace
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
    _django_utils_timezone = MagicMock()
    _django_utils_timezone.now.return_value = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)

    for mod in [
        "django", "django.conf", "django.db", "django.db.models",
        "django.db.models.functions", "django.db.models.lookups",
        "django.utils", "django.utils.timezone", "django.utils.translation",
        "django.contrib", "django.contrib.contenttypes",
        "django.contrib.contenttypes.fields", "django.contrib.contenttypes.models",
        "django.contrib.postgres", "django.contrib.postgres.fields",
        "django.contrib.postgres.indexes", "django.core", "django.core.exceptions",
        "django.core.validators",
        "django.urls", "django.http",
        "netbox", "netbox.models", "netbox.plugins",
        "netbox.api", "netbox.api.serializers",
        "netbox.graphql", "netbox.graphql.types",
        "rest_framework", "rest_framework.serializers",
        "tenancy", "tenancy.models", "tenancy.api", "tenancy.api.serializers",
        "strawberry", "strawberry_django",
        "utilities", "utilities.choices",
    ]:
        sys.modules.setdefault(mod, MagicMock())
    sys.modules["django.utils.timezone"] = _django_utils_timezone

from netbox_ssl.utils.events import build_certificate_event_payload


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_certificate(
    pk: int = 1,
    common_name: str = "example.com",
    serial_number: str = "ABCDEF123456",
    status: str = "active",
    days_remaining: int = 25,
    valid_to: datetime | None = None,
    issuer: str = "CN=Test CA",
    tenant_name: str | None = None,
    renewal_note: str = "",
    issuing_ca: object | None = None,
) -> SimpleNamespace:
    """Create a mock certificate object for testing."""
    if valid_to is None:
        valid_to = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)

    tenant = None
    if tenant_name:
        tenant = SimpleNamespace(name=tenant_name)

    mock_assignments = MagicMock()
    mock_assignments.select_related.return_value.all.return_value = []

    return SimpleNamespace(
        pk=pk,
        common_name=common_name,
        serial_number=serial_number,
        status=status,
        days_remaining=days_remaining,
        valid_to=valid_to,
        issuer=issuer,
        tenant=tenant,
        assignments=mock_assignments,
        renewal_note=renewal_note,
        issuing_ca=issuing_ca,
    )


def _make_ca(
    name: str = "DigiCert",
    renewal_instructions: str = "",
) -> SimpleNamespace:
    """Create a mock CertificateAuthority object for testing."""
    return SimpleNamespace(
        name=name,
        renewal_instructions=renewal_instructions,
    )


# ---------------------------------------------------------------------------
# Tests: Model field existence (source inspection)
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestModelFields:
    """Verify renewal fields exist in model source files."""

    def test_renewal_instructions_field_in_ca_model_source(self) -> None:
        """CertificateAuthority model source contains renewal_instructions field."""
        ca_source_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "netbox_ssl",
            "models",
            "certificate_authorities.py",
        )
        with open(ca_source_path) as f:
            source = f.read()
        assert "renewal_instructions" in source
        assert "models.TextField" in source

    def test_renewal_note_field_in_certificate_model_source(self) -> None:
        """Certificate model source contains renewal_note field."""
        cert_source_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "netbox_ssl",
            "models",
            "certificates.py",
        )
        with open(cert_source_path) as f:
            source = f.read()
        assert "renewal_note" in source
        assert "Custom renewal instructions" in source


# ---------------------------------------------------------------------------
# Tests: Event payload enrichment
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestEventPayloadRenewalInstructions:
    """Test renewal instructions inclusion in event payloads."""

    def test_payload_includes_renewal_note_from_cert(self) -> None:
        """When cert has renewal_note, payload includes it."""
        cert = _make_certificate(renewal_note="Run certbot renew --force")
        payload = build_certificate_event_payload(cert, "certificate_expiring_soon")
        assert payload["renewal_instructions"] == "Run certbot renew --force"

    def test_payload_includes_ca_instructions_when_no_cert_note(self) -> None:
        """When cert has no note but CA has instructions, payload includes CA instructions."""
        ca = _make_ca(renewal_instructions="Submit CSR via portal at https://ca.example.com")
        cert = _make_certificate(issuing_ca=ca)
        payload = build_certificate_event_payload(cert, "certificate_expiring_soon")
        assert payload["renewal_instructions"] == "Submit CSR via portal at https://ca.example.com"

    def test_payload_no_renewal_instructions_when_both_empty(self) -> None:
        """When both cert note and CA instructions are empty, payload has no key."""
        ca = _make_ca(renewal_instructions="")
        cert = _make_certificate(issuing_ca=ca, renewal_note="")
        payload = build_certificate_event_payload(cert, "certificate_expiring_soon")
        assert "renewal_instructions" not in payload

    def test_cert_note_takes_precedence_over_ca_instructions(self) -> None:
        """Cert-level renewal_note overrides CA-level renewal_instructions."""
        ca = _make_ca(renewal_instructions="Use the CA portal")
        cert = _make_certificate(
            renewal_note="Override: contact ops@example.com",
            issuing_ca=ca,
        )
        payload = build_certificate_event_payload(cert, "certificate_expiring_soon")
        assert payload["renewal_instructions"] == "Override: contact ops@example.com"

    def test_payload_no_renewal_instructions_when_no_ca(self) -> None:
        """When cert has no note and no issuing_ca, payload has no key."""
        cert = _make_certificate(renewal_note="", issuing_ca=None)
        payload = build_certificate_event_payload(cert, "certificate_expired")
        assert "renewal_instructions" not in payload

    def test_payload_no_renewal_instructions_when_ca_has_no_field(self) -> None:
        """When CA object lacks renewal_instructions attr, payload has no key."""
        ca = SimpleNamespace(name="Old CA")  # no renewal_instructions attribute
        cert = _make_certificate(renewal_note="", issuing_ca=ca)
        payload = build_certificate_event_payload(cert, "certificate_expired")
        assert "renewal_instructions" not in payload


# ---------------------------------------------------------------------------
# Tests: Serializer computed field
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestEffectiveRenewalInstructionsSerializer:
    """Test the effective_renewal_instructions serializer method logic."""

    def _get_effective_renewal_instructions(self, obj: SimpleNamespace) -> str:
        """Mirror the serializer's get_effective_renewal_instructions logic."""
        if obj.renewal_note:
            return obj.renewal_note
        if obj.issuing_ca and hasattr(obj.issuing_ca, "renewal_instructions"):
            return obj.issuing_ca.renewal_instructions or ""
        return ""

    def test_returns_cert_note_when_set(self) -> None:
        cert = _make_certificate(renewal_note="Custom note")
        assert self._get_effective_renewal_instructions(cert) == "Custom note"

    def test_returns_ca_instructions_when_no_cert_note(self) -> None:
        ca = _make_ca(renewal_instructions="CA instructions")
        cert = _make_certificate(issuing_ca=ca)
        assert self._get_effective_renewal_instructions(cert) == "CA instructions"

    def test_returns_empty_when_both_empty(self) -> None:
        ca = _make_ca(renewal_instructions="")
        cert = _make_certificate(issuing_ca=ca, renewal_note="")
        assert self._get_effective_renewal_instructions(cert) == ""

    def test_returns_empty_when_no_ca(self) -> None:
        cert = _make_certificate(issuing_ca=None, renewal_note="")
        assert self._get_effective_renewal_instructions(cert) == ""

    def test_cert_note_takes_precedence(self) -> None:
        ca = _make_ca(renewal_instructions="CA level")
        cert = _make_certificate(renewal_note="Cert level", issuing_ca=ca)
        assert self._get_effective_renewal_instructions(cert) == "Cert level"


# ---------------------------------------------------------------------------
# Tests: Migration file existence
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestMigration:
    """Verify the migration file exists and has correct content."""

    def test_migration_file_exists(self) -> None:
        migration_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "netbox_ssl",
            "migrations",
            "0012_renewal_instructions.py",
        )
        assert os.path.isfile(migration_path), f"Migration file not found at {migration_path}"

    def test_migration_contains_renewal_instructions_field(self) -> None:
        migration_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "netbox_ssl",
            "migrations",
            "0012_renewal_instructions.py",
        )
        with open(migration_path) as f:
            content = f.read()
        assert "renewal_instructions" in content
        assert "renewal_note" in content
        assert "0009_compliancetrendsnapshot" in content
