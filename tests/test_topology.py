"""
Unit tests for CertificateTopologyBuilder.

Tests tree building, color coding, and batch GFK resolution.
"""

import importlib.util
import sys
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Mock Django/NetBox before importing plugin code
# ---------------------------------------------------------------------------
try:
    _spec = importlib.util.find_spec("netbox")
    _NETBOX_AVAILABLE = _spec is not None and _spec.origin is not None
except (ValueError, ModuleNotFoundError):
    _NETBOX_AVAILABLE = False

if not _NETBOX_AVAILABLE:
    if "netbox" not in sys.modules:
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
            "netbox",
            "netbox.models",
            "netbox.plugins",
            "utilities",
            "utilities.choices",
        ]:
            sys.modules.setdefault(mod, MagicMock())

    sys.modules.setdefault("netbox_ssl.models", MagicMock())


from netbox_ssl.utils.topology import CertificateTopologyBuilder, _expiry_color


class TestExpiryColor:
    """Tests for the color coding function."""

    def test_expired(self):
        assert _expiry_color(-1) == "danger"

    def test_none(self):
        assert _expiry_color(None) == "danger"

    def test_critical(self):
        assert _expiry_color(7) == "danger"

    def test_warning(self):
        assert _expiry_color(20) == "warning"

    def test_ok(self):
        assert _expiry_color(60) == "success"

    def test_boundary_14(self):
        assert _expiry_color(14) == "warning"

    def test_boundary_30(self):
        assert _expiry_color(30) == "success"


class TestCertificateTopologyBuilder:
    """Tests for the topology tree builder."""

    def _make_builder(self):
        builder = CertificateTopologyBuilder()
        builder.Certificate = MagicMock()
        builder.CertificateAssignment = MagicMock()
        return builder

    def _make_assignment(self, cert_name, tenant_name=None, days=60):
        """Create a mock assignment with certificate."""
        cert = MagicMock()
        cert.pk = 1
        cert.common_name = cert_name
        cert.get_absolute_url.return_value = f"/cert/{cert_name}/"
        cert.status = "active"
        cert.valid_to = MagicMock()
        cert.days_remaining = days

        if tenant_name:
            tenant = MagicMock()
            tenant.pk = 100
            tenant.name = tenant_name
            cert.tenant = tenant
        else:
            cert.tenant = None

        cert.issuing_ca = MagicMock()

        assignment = MagicMock()
        assignment.certificate = cert
        assignment.certificate_id = cert.pk
        assignment.assigned_object_type_id = 10
        assignment.assigned_object_id = 20
        assignment.assigned_object_type.model = "service"
        assignment.is_primary = False

        return assignment

    @patch("netbox_ssl.utils.topology.ContentType")
    def test_empty_tree(self, mock_ct):
        """Returns empty list when no assignments or orphans."""
        builder = self._make_builder()
        builder.CertificateAssignment.objects.select_related.return_value = (
            builder.CertificateAssignment.objects.select_related.return_value
        )
        # Mock chain: select_related returns iterable of 0 items
        qs = builder.CertificateAssignment.objects.select_related.return_value
        qs.__iter__ = MagicMock(return_value=iter([]))
        qs.__len__ = MagicMock(return_value=0)

        # Mock orphan query
        cert_qs = builder.Certificate.objects.filter.return_value
        cert_qs.exclude.return_value.select_related.return_value.__getitem__ = MagicMock(return_value=[])

        result = builder.build_tree()
        assert isinstance(result, list)

    @patch("netbox_ssl.utils.topology.ContentType")
    def test_tree_with_assignments(self, mock_ct):
        """Tree contains tenant -> device -> certificate structure."""
        builder = self._make_builder()
        assignment = self._make_assignment("example.com", "Acme Corp", days=45)

        # Mock select_related chain
        qs = builder.CertificateAssignment.objects.select_related.return_value
        qs.__iter__ = MagicMock(return_value=iter([assignment]))
        qs.__len__ = MagicMock(return_value=1)

        # Mock ContentType resolution
        mock_obj = MagicMock()
        mock_obj.pk = 20
        mock_obj.__str__ = MagicMock(return_value="web-server")
        mock_obj.get_absolute_url.return_value = "/device/web-server/"

        mock_model = MagicMock()
        mock_model.objects.filter.return_value = [mock_obj]
        ct_instance = MagicMock()
        ct_instance.model_class.return_value = mock_model
        mock_ct.objects.get_for_id.return_value = ct_instance

        # Mock orphan query returning empty
        cert_qs = builder.Certificate.objects.filter.return_value
        cert_qs.exclude.return_value.select_related.return_value.__getitem__ = MagicMock(return_value=[])

        result = builder.build_tree()
        assert len(result) >= 1
        # First node should be the tenant
        tenant_node = result[0]
        assert tenant_node["tenant"]["name"] == "Acme Corp"
        assert len(tenant_node["devices"]) >= 1
        device = tenant_node["devices"][0]
        assert len(device["certificates"]) == 1
        assert device["certificates"][0]["common_name"] == "example.com"
        assert device["certificates"][0]["color"] == "success"

    def test_batch_resolve_empty(self):
        """Batch resolve returns empty dict for no assignments."""
        builder = self._make_builder()
        result = builder._batch_resolve_gfk([])
        assert result == {}
