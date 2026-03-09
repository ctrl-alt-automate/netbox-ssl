"""
Unit tests for email notification utility.

These tests verify the email rendering and sending logic
without requiring a running NetBox instance.
"""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# Mock netbox modules for local testing without NetBox
_project_root = Path(__file__).parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

for mod in ("netbox", "netbox.plugins", "netbox.models",
            "django.contrib.postgres.fields", "django.contrib.postgres.indexes",
            "utilities.choices"):
    if mod not in sys.modules:
        sys.modules[mod] = MagicMock()

# Configure Django settings minimally for these tests
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "test_settings")

from django.conf import settings

if not settings.configured:
    settings.configure(
        PLUGINS_CONFIG={},
        DEFAULT_FROM_EMAIL="test@example.com",
        TEMPLATES=[{
            "BACKEND": "django.template.backends.django.DjangoTemplates",
            "DIRS": [],
            "APP_DIRS": False,
            "OPTIONS": {"loaders": []},
        }],
    )


# ─── Sample Data ─────────────────────────────────────────────────────

SAMPLE_REPORT = {
    "summary": {
        "total_alerts": 3,
        "expired_count": 1,
        "critical_count": 1,
        "warning_count": 1,
        "thresholds": {
            "warning_days": 30,
            "critical_days": 14,
        },
        "generated_at": "2026-03-09T12:00:00+00:00",
    },
    "expired": [
        {
            "id": 1,
            "common_name": "expired.example.com",
            "serial_number": "01:AB",
            "issuer": "DigiCert Inc",
            "valid_to": "2026-03-01T00:00:00+00:00",
            "days_expired": 8,
            "tenant": "Acme Corp",
            "url": "/plugins/ssl/certificates/1/",
        },
    ],
    "critical": [
        {
            "id": 2,
            "common_name": "critical.example.com",
            "serial_number": "02:CD",
            "issuer": "Let's Encrypt",
            "valid_to": "2026-03-15T00:00:00+00:00",
            "days_remaining": 6,
            "tenant": None,
            "url": "/plugins/ssl/certificates/2/",
        },
    ],
    "warning": [
        {
            "id": 3,
            "common_name": "warning.example.com",
            "serial_number": "03:EF",
            "issuer": "Sectigo",
            "valid_to": "2026-04-01T00:00:00+00:00",
            "days_remaining": 23,
            "tenant": "Beta Inc",
            "url": "/plugins/ssl/certificates/3/",
        },
    ],
}

EMPTY_REPORT = {
    "summary": {
        "total_alerts": 0,
        "expired_count": 0,
        "critical_count": 0,
        "warning_count": 0,
        "thresholds": {"warning_days": 30, "critical_days": 14},
        "generated_at": "2026-03-09T12:00:00+00:00",
    },
    "expired": [],
    "critical": [],
    "warning": [],
}


def _make_settings_mock(enabled: bool = True, recipients: list | None = None):
    """Create a mock settings object."""
    mock = MagicMock()
    mock.PLUGINS_CONFIG = {
        "netbox_ssl": {
            "notification_email_enabled": enabled,
            "notification_email_recipients": recipients or ["admin@example.com"],
            "notification_email_subject_prefix": "[NetBox SSL]",
        }
    }
    mock.DEFAULT_FROM_EMAIL = "netbox@example.com"
    return mock


class TestSendExpiryReport:
    @patch("netbox_ssl.utils.email.EmailMultiAlternatives")
    @patch("netbox_ssl.utils.email.render_to_string", side_effect=lambda t, c: f"rendered:{t}")
    @patch("netbox_ssl.utils.email.settings", new=_make_settings_mock(True))
    def test_sends_email_when_enabled(self, mock_render, mock_email_cls):
        from netbox_ssl.utils.email import send_expiry_report

        mock_msg = MagicMock()
        mock_email_cls.return_value = mock_msg

        result = send_expiry_report(SAMPLE_REPORT)

        assert result is True
        mock_email_cls.assert_called_once()
        args = mock_email_cls.call_args
        assert "[NetBox SSL]" in args[0][0]
        assert "admin@example.com" in args[0][3]
        mock_msg.attach_alternative.assert_called_once()
        mock_msg.send.assert_called_once()

    @patch("netbox_ssl.utils.email.render_to_string", side_effect=lambda t, c: f"rendered:{t}")
    @patch("netbox_ssl.utils.email.settings", new=_make_settings_mock(False))
    def test_skips_when_disabled(self, mock_render):
        from netbox_ssl.utils.email import send_expiry_report

        result = send_expiry_report(SAMPLE_REPORT)
        assert result is False

    @patch("netbox_ssl.utils.email.render_to_string", side_effect=lambda t, c: f"rendered:{t}")
    @patch("netbox_ssl.utils.email.settings", new=_make_settings_mock(True, []))
    def test_skips_when_no_recipients(self, mock_render):
        from netbox_ssl.utils.email import send_expiry_report

        result = send_expiry_report(SAMPLE_REPORT)
        assert result is False

    @patch("netbox_ssl.utils.email.render_to_string", side_effect=lambda t, c: f"rendered:{t}")
    @patch("netbox_ssl.utils.email.settings", new=_make_settings_mock(True))
    def test_skips_when_no_alerts(self, mock_render):
        from netbox_ssl.utils.email import send_expiry_report

        result = send_expiry_report(EMPTY_REPORT)
        assert result is False

    @patch("netbox_ssl.utils.email.EmailMultiAlternatives")
    @patch("netbox_ssl.utils.email.render_to_string", side_effect=lambda t, c: f"rendered:{t}")
    @patch("netbox_ssl.utils.email.settings", new=_make_settings_mock(True))
    def test_uses_override_recipients(self, mock_render, mock_email_cls):
        from netbox_ssl.utils.email import send_expiry_report

        mock_msg = MagicMock()
        mock_email_cls.return_value = mock_msg

        result = send_expiry_report(SAMPLE_REPORT, recipients=["custom@example.com"])

        assert result is True
        args = mock_email_cls.call_args
        assert "custom@example.com" in args[0][3]

    @patch("netbox_ssl.utils.email.EmailMultiAlternatives")
    @patch("netbox_ssl.utils.email.render_to_string", side_effect=lambda t, c: f"rendered:{t}")
    @patch("netbox_ssl.utils.email.settings", new=_make_settings_mock(True))
    def test_includes_base_url_in_context(self, mock_render, mock_email_cls):
        from netbox_ssl.utils.email import send_expiry_report

        mock_msg = MagicMock()
        mock_email_cls.return_value = mock_msg

        send_expiry_report(SAMPLE_REPORT, base_url="https://netbox.example.com")

        render_calls = mock_render.call_args_list
        for call in render_calls:
            context = call[0][1]
            assert context["base_url"] == "https://netbox.example.com"

    @patch("netbox_ssl.utils.email.EmailMultiAlternatives")
    @patch("netbox_ssl.utils.email.render_to_string", side_effect=lambda t, c: f"rendered:{t}")
    @patch("netbox_ssl.utils.email.settings", new=_make_settings_mock(True))
    def test_handles_send_failure(self, mock_render, mock_email_cls):
        from netbox_ssl.utils.email import send_expiry_report

        mock_msg = MagicMock()
        mock_msg.send.side_effect = Exception("SMTP error")
        mock_email_cls.return_value = mock_msg

        result = send_expiry_report(SAMPLE_REPORT)
        assert result is False
