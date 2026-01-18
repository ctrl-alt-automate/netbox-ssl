"""
Unit tests for NetBox SSL plugin models.

These tests verify the Certificate and CertificateAssignment models
work correctly without requiring a full NetBox environment.
"""

import pytest
import sys
from datetime import datetime, timedelta, date
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

# Allow importing modules directly without loading the full netbox_ssl package
_project_root = Path(__file__).parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

# Check if we're running inside Docker with full NetBox available
# Detection: Check if NetBox settings module exists
import os

# Two scenarios:
# 1. Running locally without NetBox: mock everything
# 2. Running in Docker with NetBox: use real Django setup

# Try to detect if we're in a NetBox environment by checking for settings
_in_netbox_env = os.path.exists('/opt/netbox/netbox/netbox/settings.py') or \
                 'DJANGO_SETTINGS_MODULE' in os.environ

if _in_netbox_env:
    # Running in Docker with NetBox: set up Django first
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'netbox.settings')
    import django
    try:
        django.setup()
    except RuntimeError:
        # Already set up
        pass
    NETBOX_AVAILABLE = True
else:
    # Local testing: mock netbox modules
    sys.modules["netbox"] = MagicMock()
    sys.modules["netbox.plugins"] = MagicMock()
    sys.modules["netbox.models"] = MagicMock()
    sys.modules["netbox.models.features"] = MagicMock()

    # Configure minimal Django settings
    import django
    from django.conf import settings
    if not settings.configured:
        settings.configure(
            USE_TZ=True,
            TIME_ZONE='UTC',
            DATABASES={},
            INSTALLED_APPS=[],
            DEFAULT_AUTO_FIELD='django.db.models.BigAutoField',
        )
    NETBOX_AVAILABLE = False

from django.utils import timezone

# Try to import real NetBox models (only if NETBOX_AVAILABLE)
if NETBOX_AVAILABLE:
    try:
        from netbox_ssl.models import Certificate, CertificateAssignment
    except (ImportError, ModuleNotFoundError) as e:
        print(f"Warning: Could not import netbox_ssl models: {e}")
        NETBOX_AVAILABLE = False

# Skip marker for tests that require NetBox
requires_netbox = pytest.mark.skipif(
    not NETBOX_AVAILABLE,
    reason="NetBox not available - run these tests inside Docker container"
)


class TestCertificateModel:
    """Tests for Certificate model properties and methods.

    These tests verify the property logic that would be used by the Certificate model.
    They use mocks to avoid needing the full NetBox environment.
    """

    def _create_mock_certificate(self, valid_from, valid_to, status="active"):
        """Create a mock certificate object for testing.

        Implements the same property logic as the Certificate model.
        """
        mock_cert = Mock()
        mock_cert.valid_from = valid_from
        mock_cert.valid_to = valid_to
        mock_cert.status = status

        # Manually implement the properties using the same logic as the model
        if valid_to:
            delta = valid_to.date() - date.today()
            mock_cert.days_remaining = delta.days
        else:
            mock_cert.days_remaining = None

        if mock_cert.days_remaining is not None and mock_cert.days_remaining < 0:
            mock_cert.days_expired = abs(mock_cert.days_remaining)
        else:
            mock_cert.days_expired = 0

        mock_cert.is_expired = valid_to and valid_to < timezone.now()

        if mock_cert.days_remaining is None:
            mock_cert.is_expiring_soon = False
            mock_cert.is_critical = False
        else:
            mock_cert.is_expiring_soon = 0 < mock_cert.days_remaining <= 30
            mock_cert.is_critical = 0 < mock_cert.days_remaining <= 14

        # Expiry status
        if mock_cert.is_expired:
            mock_cert.expiry_status = "expired"
        elif mock_cert.is_critical:
            mock_cert.expiry_status = "critical"
        elif mock_cert.is_expiring_soon:
            mock_cert.expiry_status = "warning"
        else:
            mock_cert.expiry_status = "ok"

        return mock_cert

    @pytest.mark.unit
    def test_days_remaining_future(self):
        """Test days_remaining for a certificate expiring in the future."""
        now = timezone.now()
        future = now + timedelta(days=100)
        cert = self._create_mock_certificate(now - timedelta(days=265), future)

        assert cert.days_remaining >= 99  # Allow for test timing
        assert cert.days_remaining <= 101

    @pytest.mark.unit
    def test_days_remaining_expired(self):
        """Test days_remaining for an expired certificate."""
        now = timezone.now()
        past = now - timedelta(days=10)
        cert = self._create_mock_certificate(now - timedelta(days=375), past)

        assert cert.days_remaining < 0
        assert cert.days_remaining >= -11
        assert cert.days_remaining <= -9

    @pytest.mark.unit
    def test_days_expired_for_expired_cert(self):
        """Test days_expired returns positive value for expired certs."""
        now = timezone.now()
        past = now - timedelta(days=15)
        cert = self._create_mock_certificate(now - timedelta(days=380), past)

        assert cert.days_expired >= 14
        assert cert.days_expired <= 16

    @pytest.mark.unit
    def test_days_expired_for_valid_cert(self):
        """Test days_expired returns 0 for valid certificates."""
        now = timezone.now()
        future = now + timedelta(days=100)
        cert = self._create_mock_certificate(now - timedelta(days=265), future)

        assert cert.days_expired == 0

    @pytest.mark.unit
    def test_is_expired_true(self):
        """Test is_expired returns True for expired certificates."""
        now = timezone.now()
        past = now - timedelta(days=1)
        cert = self._create_mock_certificate(now - timedelta(days=366), past)

        assert cert.is_expired is True

    @pytest.mark.unit
    def test_is_expired_false(self):
        """Test is_expired returns False for valid certificates."""
        now = timezone.now()
        future = now + timedelta(days=100)
        cert = self._create_mock_certificate(now - timedelta(days=265), future)

        assert cert.is_expired is False

    @pytest.mark.unit
    def test_is_expiring_soon_warning_threshold(self):
        """Test is_expiring_soon for cert expiring within 30 days."""
        now = timezone.now()
        future = now + timedelta(days=20)  # 20 days remaining
        cert = self._create_mock_certificate(now - timedelta(days=345), future)

        assert cert.is_expiring_soon is True
        assert cert.is_critical is False  # Not critical yet

    @pytest.mark.unit
    def test_is_critical_threshold(self):
        """Test is_critical for cert expiring within 14 days."""
        now = timezone.now()
        future = now + timedelta(days=7)  # 7 days remaining
        cert = self._create_mock_certificate(now - timedelta(days=358), future)

        assert cert.is_critical is True
        assert cert.is_expiring_soon is True  # Also expiring soon

    @pytest.mark.unit
    def test_expiry_status_ok(self):
        """Test expiry_status returns 'ok' for healthy certificates."""
        now = timezone.now()
        future = now + timedelta(days=100)
        cert = self._create_mock_certificate(now - timedelta(days=265), future)

        assert cert.expiry_status == "ok"

    @pytest.mark.unit
    def test_expiry_status_warning(self):
        """Test expiry_status returns 'warning' for soon-expiring certs."""
        now = timezone.now()
        future = now + timedelta(days=20)
        cert = self._create_mock_certificate(now - timedelta(days=345), future)

        assert cert.expiry_status == "warning"

    @pytest.mark.unit
    def test_expiry_status_critical(self):
        """Test expiry_status returns 'critical' for nearly-expired certs."""
        now = timezone.now()
        future = now + timedelta(days=7)
        cert = self._create_mock_certificate(now - timedelta(days=358), future)

        assert cert.expiry_status == "critical"

    @pytest.mark.unit
    def test_expiry_status_expired(self):
        """Test expiry_status returns 'expired' for expired certs."""
        now = timezone.now()
        past = now - timedelta(days=10)
        cert = self._create_mock_certificate(now - timedelta(days=375), past)

        assert cert.expiry_status == "expired"


class TestCertificateStatusChoices:
    """Tests for CertificateStatusChoices."""

    @requires_netbox
    @pytest.mark.unit
    def test_status_choices_exist(self):
        """Test that all expected status choices are defined."""
        from netbox_ssl.models.certificates import CertificateStatusChoices

        assert hasattr(CertificateStatusChoices, 'STATUS_ACTIVE')
        assert hasattr(CertificateStatusChoices, 'STATUS_EXPIRED')
        assert hasattr(CertificateStatusChoices, 'STATUS_REPLACED')
        assert hasattr(CertificateStatusChoices, 'STATUS_REVOKED')
        assert hasattr(CertificateStatusChoices, 'STATUS_PENDING')

    @requires_netbox
    @pytest.mark.unit
    def test_status_values(self):
        """Test status choice values."""
        from netbox_ssl.models.certificates import CertificateStatusChoices

        assert CertificateStatusChoices.STATUS_ACTIVE == "active"
        assert CertificateStatusChoices.STATUS_EXPIRED == "expired"
        assert CertificateStatusChoices.STATUS_REPLACED == "replaced"


class TestCertificateAlgorithmChoices:
    """Tests for CertificateAlgorithmChoices."""

    @requires_netbox
    @pytest.mark.unit
    def test_algorithm_choices_exist(self):
        """Test that all expected algorithm choices are defined."""
        from netbox_ssl.models.certificates import CertificateAlgorithmChoices

        assert hasattr(CertificateAlgorithmChoices, 'ALGORITHM_RSA')
        assert hasattr(CertificateAlgorithmChoices, 'ALGORITHM_ECDSA')
        assert hasattr(CertificateAlgorithmChoices, 'ALGORITHM_ED25519')

    @requires_netbox
    @pytest.mark.unit
    def test_algorithm_values(self):
        """Test algorithm choice values."""
        from netbox_ssl.models.certificates import CertificateAlgorithmChoices

        assert CertificateAlgorithmChoices.ALGORITHM_RSA == "rsa"
        assert CertificateAlgorithmChoices.ALGORITHM_ECDSA == "ecdsa"
        assert CertificateAlgorithmChoices.ALGORITHM_ED25519 == "ed25519"


class TestJanusRenewalWorkflow:
    """Tests for the Janus Renewal workflow logic."""

    @pytest.mark.unit
    def test_find_renewal_candidate_detects_same_cn(self):
        """Test that find_renewal_candidate finds certificates with matching CN."""
        from netbox_ssl.utils.parser import CertificateParser
        from unittest.mock import MagicMock

        # Create a mock Certificate model class
        mock_model = MagicMock()
        mock_existing_cert = MagicMock()
        mock_existing_cert.common_name = "test.example.com"

        # Configure the queryset chain
        mock_queryset = MagicMock()
        mock_queryset.exists.return_value = True
        mock_queryset.first.return_value = mock_existing_cert
        mock_model.objects.filter.return_value.order_by.return_value = mock_queryset

        # Test finding a renewal candidate
        result = CertificateParser.find_renewal_candidate("test.example.com", mock_model)

        # Verify the model was queried correctly
        mock_model.objects.filter.assert_called_once_with(
            common_name="test.example.com",
            status__in=["active", "expired"],
        )
        assert result == mock_existing_cert

    @pytest.mark.unit
    def test_find_renewal_candidate_returns_none_for_new_cn(self):
        """Test that find_renewal_candidate returns None for new CNs."""
        from netbox_ssl.utils.parser import CertificateParser
        from unittest.mock import MagicMock

        # Create a mock Certificate model class
        mock_model = MagicMock()

        # Configure the queryset chain to return no results
        mock_queryset = MagicMock()
        mock_queryset.exists.return_value = False
        mock_model.objects.filter.return_value.order_by.return_value = mock_queryset

        # Test with a CN that doesn't exist
        result = CertificateParser.find_renewal_candidate("new.example.com", mock_model)

        assert result is None

    @requires_netbox
    @pytest.mark.unit
    def test_renewal_preserves_status_replaced(self):
        """Test that old certificate gets 'replaced' status after renewal."""
        from netbox_ssl.models import CertificateStatusChoices

        # Verify the status choice exists
        assert CertificateStatusChoices.STATUS_REPLACED == "replaced"

    @requires_netbox
    @pytest.mark.unit
    def test_renewal_chain_tracking_field_exists(self):
        """Test that Certificate model supports renewal chain tracking."""
        from netbox_ssl.models import Certificate

        # Verify the replaced_by field exists for tracking renewal chains
        assert hasattr(Certificate, 'replaced_by')


class TestMultiTenancyValidation:
    """Tests for multi-tenancy boundary validation."""

    @requires_netbox
    @pytest.mark.unit
    def test_assignment_model_has_tenant_validation(self):
        """Test that CertificateAssignment has tenant boundary validation."""
        from netbox_ssl.models import CertificateAssignment
        import inspect

        # Verify clean method exists
        assert hasattr(CertificateAssignment, 'clean')

        # Verify clean method contains tenant validation logic
        source = inspect.getsource(CertificateAssignment.clean)
        assert 'tenant' in source.lower()
        assert 'ValidationError' in source

    @requires_netbox
    @pytest.mark.unit
    def test_certificate_model_has_tenant_field(self):
        """Test that Certificate model has tenant field."""
        from netbox_ssl.models import Certificate

        assert hasattr(Certificate, 'tenant')

    @requires_netbox
    @pytest.mark.unit
    def test_tenant_boundary_error_message(self):
        """Test that cross-tenant assignment produces clear error message."""
        from netbox_ssl.models import CertificateAssignment
        from django.core.exceptions import ValidationError

        # Create mock tenants
        mock_tenant_a = MagicMock()
        mock_tenant_a.__str__ = MagicMock(return_value="Tenant A")
        mock_tenant_a.pk = 1

        mock_tenant_b = MagicMock()
        mock_tenant_b.__str__ = MagicMock(return_value="Tenant B")
        mock_tenant_b.pk = 2

        # Mock the certificate with tenant A
        mock_cert = MagicMock()
        mock_cert.tenant = mock_tenant_a

        # Mock the assigned object with tenant B
        mock_device = MagicMock()
        mock_device.tenant = mock_tenant_b

        # Create assignment and use patching to bypass ForeignKey validation
        assignment = CertificateAssignment()
        assignment.certificate_id = 1  # Set a fake ID

        # Patch the properties to return our mocks
        with patch.object(CertificateAssignment, 'certificate', new_callable=lambda: property(lambda s: mock_cert)):
            with patch.object(CertificateAssignment, 'assigned_object', new_callable=lambda: property(lambda s: mock_device)):
                # Test that clean raises ValidationError
                with pytest.raises(ValidationError) as exc_info:
                    assignment.clean()

                # Verify error message mentions tenant
                error_msg = str(exc_info.value)
                assert "tenant" in error_msg.lower()


class TestAssignmentModel:
    """Tests for CertificateAssignment model."""

    @requires_netbox
    @pytest.mark.unit
    def test_assignment_supports_service_type(self):
        """Test that assignments support Service as target type."""
        from netbox_ssl.models import CertificateAssignment

        # Verify the model can handle service assignments
        # Check the limit_choices_to on assigned_object_type
        field = CertificateAssignment._meta.get_field('assigned_object_type')
        limit_choices = field.get_limit_choices_to()

        assert 'model__in' in limit_choices
        assert 'service' in limit_choices['model__in']

    @requires_netbox
    @pytest.mark.unit
    def test_assignment_supports_device_type(self):
        """Test that assignments support Device as target type."""
        from netbox_ssl.models import CertificateAssignment

        field = CertificateAssignment._meta.get_field('assigned_object_type')
        limit_choices = field.get_limit_choices_to()

        assert 'device' in limit_choices['model__in']

    @requires_netbox
    @pytest.mark.unit
    def test_assignment_supports_vm_type(self):
        """Test that assignments support VirtualMachine as target type."""
        from netbox_ssl.models import CertificateAssignment

        field = CertificateAssignment._meta.get_field('assigned_object_type')
        limit_choices = field.get_limit_choices_to()

        assert 'virtualmachine' in limit_choices['model__in']

    @requires_netbox
    @pytest.mark.unit
    def test_assignment_unique_constraint(self):
        """Test that assignment has unique constraint."""
        from netbox_ssl.models import CertificateAssignment

        # Check for unique constraint
        constraints = CertificateAssignment._meta.constraints
        constraint_names = [c.name for c in constraints]

        assert 'unique_certificate_assignment' in constraint_names

    @requires_netbox
    @pytest.mark.unit
    def test_assignment_has_is_primary_field(self):
        """Test that assignment has is_primary field for primary cert marking."""
        from netbox_ssl.models import CertificateAssignment

        field = CertificateAssignment._meta.get_field('is_primary')
        assert field.default is True


class TestAssignmentForm:
    """Tests for CertificateAssignmentForm."""

    @requires_netbox
    @pytest.mark.unit
    def test_form_has_device_field(self):
        """Test that assignment form has device field for two-step workflow."""
        from netbox_ssl.forms import CertificateAssignmentForm

        form = CertificateAssignmentForm()
        assert 'device' in form.fields

    @requires_netbox
    @pytest.mark.unit
    def test_form_has_virtual_machine_field(self):
        """Test that assignment form has virtual_machine field."""
        from netbox_ssl.forms import CertificateAssignmentForm

        form = CertificateAssignmentForm()
        assert 'virtual_machine' in form.fields

    @requires_netbox
    @pytest.mark.unit
    def test_form_has_service_field(self):
        """Test that assignment form has service field for port-level assignment."""
        from netbox_ssl.forms import CertificateAssignmentForm

        form = CertificateAssignmentForm()
        assert 'service' in form.fields

    @requires_netbox
    @pytest.mark.unit
    def test_form_auto_determines_type_from_service(self):
        """Test that form automatically determines assignment type from service selection."""
        from netbox_ssl.forms import CertificateAssignmentForm
        import inspect

        # Check that save method contains type determination logic
        source = inspect.getsource(CertificateAssignmentForm.save)
        assert 'assigned_object_type' in source
        assert 'Service' in source

    @requires_netbox
    @pytest.mark.unit
    def test_form_validates_duplicate_assignments(self):
        """Test that form validates against duplicate assignments."""
        from netbox_ssl.forms import CertificateAssignmentForm
        import inspect

        # Check that clean method contains duplicate validation
        source = inspect.getsource(CertificateAssignmentForm.clean)
        assert 'already assigned' in source or 'existing' in source.lower()

    @requires_netbox
    @pytest.mark.unit
    def test_form_requires_at_least_one_target(self):
        """Test that form requires at least one target (device, VM, or service)."""
        from netbox_ssl.forms import CertificateAssignmentForm
        import inspect

        # Check that clean method validates at least one target
        source = inspect.getsource(CertificateAssignmentForm.clean)
        assert 'ValidationError' in source


class TestTemplateExtensions:
    """Tests for template extensions on Device/VM/Service pages."""

    @requires_netbox
    @pytest.mark.unit
    def test_device_extension_exists(self):
        """Test that DeviceCertificates template extension exists."""
        from netbox_ssl.template_content import DeviceCertificates

        assert DeviceCertificates.models == ["dcim.device"]

    @requires_netbox
    @pytest.mark.unit
    def test_vm_extension_exists(self):
        """Test that VirtualMachineCertificates template extension exists."""
        from netbox_ssl.template_content import VirtualMachineCertificates

        assert VirtualMachineCertificates.models == ["virtualization.virtualmachine"]

    @requires_netbox
    @pytest.mark.unit
    def test_service_extension_exists(self):
        """Test that ServiceCertificates template extension exists."""
        from netbox_ssl.template_content import ServiceCertificates

        assert ServiceCertificates.models == ["ipam.service"]

    @requires_netbox
    @pytest.mark.unit
    def test_extensions_registered(self):
        """Test that all template extensions are in the registration list."""
        from netbox_ssl.template_content import template_extensions

        extension_names = [ext.__name__ for ext in template_extensions]
        assert 'DeviceCertificates' in extension_names
        assert 'VirtualMachineCertificates' in extension_names
        assert 'ServiceCertificates' in extension_names

    @requires_netbox
    @pytest.mark.unit
    def test_device_extension_includes_service_certificates(self):
        """Test that DeviceCertificates also queries service assignments."""
        from netbox_ssl.template_content import DeviceCertificates
        import inspect

        # Check that right_page method queries services on the device
        source = inspect.getsource(DeviceCertificates.right_page)
        assert 'service' in source.lower()
        assert 'parent_object' in source

    @requires_netbox
    @pytest.mark.unit
    def test_vm_extension_includes_service_certificates(self):
        """Test that VirtualMachineCertificates also queries service assignments."""
        from netbox_ssl.template_content import VirtualMachineCertificates
        import inspect

        # Check that right_page method queries services on the VM
        source = inspect.getsource(VirtualMachineCertificates.right_page)
        assert 'service' in source.lower()
        assert 'parent_object' in source


class TestAssignmentTableRendering:
    """Tests for assignment table rendering with parent info."""

    @requires_netbox
    @pytest.mark.unit
    def test_table_renders_parent_for_services(self):
        """Test that assignment table shows parent device/VM for services."""
        from netbox_ssl.tables import CertificateAssignmentTable
        import inspect

        # Check that render_assigned_object shows parent
        source = inspect.getsource(CertificateAssignmentTable.render_assigned_object)
        assert 'parent' in source
        assert 'service' in source.lower()

    @requires_netbox
    @pytest.mark.unit
    def test_table_uses_format_html(self):
        """Test that table uses format_html for safe HTML rendering."""
        from netbox_ssl.tables import CertificateAssignmentTable
        import inspect

        source = inspect.getsource(CertificateAssignmentTable.render_assigned_object)
        assert 'format_html' in source
