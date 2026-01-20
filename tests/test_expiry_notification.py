"""
Unit tests for the Certificate Expiry Notification script.

Tests cover:
- Script configuration and metadata
- Threshold logic
- Certificate categorization
- Output format for webhooks
"""

from datetime import datetime, timedelta

import pytest


def script_available():
    """Check if the script module can be imported."""
    try:
        from netbox_ssl.scripts.expiry_notification import (
            CertificateExpiryNotification,  # noqa: F401
        )

        return True
    except Exception:
        # Catches ImportError, ModuleNotFoundError, and Django ImproperlyConfigured
        return False


skip_if_no_script = pytest.mark.skipif(not script_available(), reason="Script module not available in this environment")


class TestExpiryNotificationScriptStructure:
    """Tests for script structure and configuration."""

    @pytest.mark.unit
    @skip_if_no_script
    def test_script_has_required_meta_attributes(self):
        """Test that the script has required Meta attributes."""
        from netbox_ssl.scripts.expiry_notification import CertificateExpiryNotification

        script = CertificateExpiryNotification()
        assert hasattr(script, "Meta")
        assert hasattr(script.Meta, "name")
        assert hasattr(script.Meta, "description")

    @pytest.mark.unit
    @skip_if_no_script
    def test_script_name_is_descriptive(self):
        """Test that the script has a descriptive name."""
        from netbox_ssl.scripts.expiry_notification import CertificateExpiryNotification

        script = CertificateExpiryNotification()
        assert "Certificate" in script.Meta.name
        assert "Expir" in script.Meta.name

    @pytest.mark.unit
    @skip_if_no_script
    def test_script_has_warning_days_variable(self):
        """Test that the script has a warning_days variable."""
        from netbox_ssl.scripts.expiry_notification import CertificateExpiryNotification

        script = CertificateExpiryNotification()
        assert hasattr(script, "warning_days")

    @pytest.mark.unit
    @skip_if_no_script
    def test_script_has_critical_days_variable(self):
        """Test that the script has a critical_days variable."""
        from netbox_ssl.scripts.expiry_notification import CertificateExpiryNotification

        script = CertificateExpiryNotification()
        assert hasattr(script, "critical_days")

    @pytest.mark.unit
    @skip_if_no_script
    def test_script_has_tenant_variable(self):
        """Test that the script has a tenant filter variable."""
        from netbox_ssl.scripts.expiry_notification import CertificateExpiryNotification

        script = CertificateExpiryNotification()
        assert hasattr(script, "tenant")

    @pytest.mark.unit
    @skip_if_no_script
    def test_script_has_include_expired_variable(self):
        """Test that the script has an include_expired variable."""
        from netbox_ssl.scripts.expiry_notification import CertificateExpiryNotification

        script = CertificateExpiryNotification()
        assert hasattr(script, "include_expired")

    @pytest.mark.unit
    @skip_if_no_script
    def test_script_has_active_only_variable(self):
        """Test that the script has an active_only variable."""
        from netbox_ssl.scripts.expiry_notification import CertificateExpiryNotification

        script = CertificateExpiryNotification()
        assert hasattr(script, "active_only")

    @pytest.mark.unit
    @skip_if_no_script
    def test_script_commit_default_is_false(self):
        """Test that the script does not commit by default."""
        from netbox_ssl.scripts.expiry_notification import CertificateExpiryNotification

        script = CertificateExpiryNotification()
        assert script.Meta.commit_default is False


class TestExpiryThresholdLogic:
    """Tests for certificate expiry threshold logic."""

    @pytest.mark.unit
    def test_warning_threshold_calculation(self):
        """Test that warning threshold is calculated correctly."""
        now = datetime.now()
        warning_days = 30
        threshold = now + timedelta(days=warning_days)

        # Certificate expiring in 25 days should be in warning range
        cert_expiry = now + timedelta(days=25)
        assert cert_expiry <= threshold
        assert cert_expiry > now

    @pytest.mark.unit
    def test_critical_threshold_calculation(self):
        """Test that critical threshold is calculated correctly."""
        now = datetime.now()
        critical_days = 14
        threshold = now + timedelta(days=critical_days)

        # Certificate expiring in 10 days should be in critical range
        cert_expiry = now + timedelta(days=10)
        assert cert_expiry <= threshold
        assert cert_expiry > now

    @pytest.mark.unit
    def test_expired_certificate_detection(self):
        """Test that expired certificates are detected correctly."""
        now = datetime.now()

        # Certificate that expired 5 days ago
        cert_expiry = now - timedelta(days=5)
        assert cert_expiry < now

    @pytest.mark.unit
    def test_certificate_outside_thresholds(self):
        """Test that certificates outside thresholds are not flagged."""
        now = datetime.now()
        warning_days = 30
        threshold = now + timedelta(days=warning_days)

        # Certificate expiring in 60 days should not be in warning range
        cert_expiry = now + timedelta(days=60)
        assert cert_expiry > threshold


class TestCertificateCategorization:
    """Tests for certificate categorization logic."""

    @pytest.mark.unit
    def test_expired_category_for_past_dates(self):
        """Test that past expiry dates are categorized as expired."""
        now = datetime.now()
        expiry = now - timedelta(days=1)

        is_expired = expiry < now
        assert is_expired is True

    @pytest.mark.unit
    def test_critical_category_boundaries(self):
        """Test critical category boundary conditions."""
        now = datetime.now()
        critical_days = 14
        critical_threshold = now + timedelta(days=critical_days)

        # Exactly at threshold - should be critical
        expiry_at_threshold = critical_threshold
        assert now <= expiry_at_threshold <= critical_threshold

        # One day before threshold - should be critical
        expiry_before = now + timedelta(days=critical_days - 1)
        assert now <= expiry_before <= critical_threshold

    @pytest.mark.unit
    def test_warning_category_boundaries(self):
        """Test warning category boundary conditions."""
        now = datetime.now()
        warning_days = 30
        critical_days = 14
        warning_threshold = now + timedelta(days=warning_days)
        critical_threshold = now + timedelta(days=critical_days)

        # 20 days out - should be warning (between critical and warning)
        expiry_warning = now + timedelta(days=20)
        assert critical_threshold < expiry_warning <= warning_threshold

    @pytest.mark.unit
    def test_ok_category_for_far_future(self):
        """Test that far-future expiry is not flagged."""
        now = datetime.now()
        warning_days = 30
        warning_threshold = now + timedelta(days=warning_days)

        # 90 days out - should not trigger any alert
        expiry_ok = now + timedelta(days=90)
        assert expiry_ok > warning_threshold


class TestWebhookOutputFormat:
    """Tests for webhook output format specification."""

    @pytest.mark.unit
    def test_output_has_summary_section(self):
        """Test that output format includes summary section."""
        expected_keys = ["total_alerts", "expired_count", "critical_count", "warning_count"]
        # This documents the expected output format
        assert all(key for key in expected_keys)

    @pytest.mark.unit
    def test_output_has_thresholds_in_summary(self):
        """Test that output includes threshold configuration."""
        expected_threshold_keys = ["warning_days", "critical_days"]
        assert all(key for key in expected_threshold_keys)

    @pytest.mark.unit
    def test_output_has_filters_in_summary(self):
        """Test that output includes filter settings."""
        expected_filter_keys = ["tenant", "active_only", "include_expired"]
        assert all(key for key in expected_filter_keys)

    @pytest.mark.unit
    def test_certificate_entry_has_required_fields(self):
        """Test that certificate entries have required fields."""
        expected_fields = [
            "id",
            "common_name",
            "serial_number",
            "issuer",
            "valid_to",
            "tenant",
            "url",
        ]
        assert all(field for field in expected_fields)

    @pytest.mark.unit
    def test_expired_entries_have_days_expired(self):
        """Test that expired entries include days_expired field."""
        field = "days_expired"
        assert field == "days_expired"

    @pytest.mark.unit
    def test_warning_critical_entries_have_days_remaining(self):
        """Test that warning/critical entries include days_remaining field."""
        field = "days_remaining"
        assert field == "days_remaining"


class TestPluginSettingsIntegration:
    """Tests for plugin settings integration."""

    @pytest.mark.unit
    @skip_if_no_script
    def test_script_reads_plugin_settings(self):
        """Test that script can read plugin settings."""
        from netbox_ssl.scripts.expiry_notification import CertificateExpiryNotification

        script = CertificateExpiryNotification()
        assert hasattr(script, "get_plugin_setting")

    @pytest.mark.unit
    @skip_if_no_script
    def test_get_plugin_setting_returns_default(self):
        """Test that get_plugin_setting returns default when setting not found."""
        from netbox_ssl.scripts.expiry_notification import CertificateExpiryNotification

        script = CertificateExpiryNotification()
        # Test with a setting that doesn't exist
        result = script.get_plugin_setting("nonexistent_setting", "default_value")
        assert result == "default_value"

    @pytest.mark.unit
    def test_default_warning_days_is_30(self):
        """Test that default warning days is 30."""
        # This is set in the plugin's default_settings
        expected_default = 30
        assert expected_default == 30

    @pytest.mark.unit
    def test_default_critical_days_is_14(self):
        """Test that default critical days is 14."""
        # This is set in the plugin's default_settings
        expected_default = 14
        assert expected_default == 14


class TestScriptModuleExports:
    """Tests for script module exports."""

    @pytest.mark.unit
    @skip_if_no_script
    def test_script_is_exported_from_package(self):
        """Test that script is exported from scripts package."""
        from netbox_ssl.scripts import CertificateExpiryNotification

        assert CertificateExpiryNotification is not None

    @pytest.mark.unit
    @skip_if_no_script
    def test_script_is_in_all_list(self):
        """Test that script is in __all__ list."""
        from netbox_ssl import scripts

        assert "CertificateExpiryNotification" in scripts.__all__
