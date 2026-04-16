"""
Unit tests for shared URL validation / SSRF protection.

Tests HTTPS enforcement, loopback/private IP blocking, and DNS resolution checks.
"""

import importlib.util
import sys
from unittest.mock import MagicMock, patch

import pytest

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
        "netbox",
        "netbox.models",
        "netbox.plugins",
        "utilities",
        "utilities.choices",
    ]:
        if mod not in sys.modules:
            sys.modules[mod] = MagicMock()

from netbox_ssl.utils.url_validation import URLValidationError, validate_https_url

pytestmark = pytest.mark.unit


class TestHTTPSEnforcement:
    """Test that only HTTPS URLs are accepted."""

    def test_https_url_accepted(self):
        """HTTPS URL with public domain does not raise."""
        # Mock DNS to return a public IP
        with patch("netbox_ssl.utils.url_validation.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [(None, None, None, None, ("93.184.216.34", 443))]
            validate_https_url("https://example.com/path")

    def test_http_url_rejected(self):
        with pytest.raises(URLValidationError, match="Only HTTPS"):
            validate_https_url("http://example.com")

    def test_ftp_url_rejected(self):
        with pytest.raises(URLValidationError, match="Only HTTPS"):
            validate_https_url("ftp://example.com")

    def test_empty_scheme_rejected(self):
        with pytest.raises(URLValidationError):
            validate_https_url("://example.com")


class TestLoopbackBlocking:
    """Test that loopback and well-known local addresses are blocked."""

    def test_localhost_rejected(self):
        with pytest.raises(URLValidationError, match="loopback"):
            validate_https_url("https://localhost/api")

    def test_127_0_0_1_rejected(self):
        with pytest.raises(URLValidationError, match="loopback"):
            validate_https_url("https://127.0.0.1/api")

    def test_ipv6_loopback_rejected(self):
        with pytest.raises(URLValidationError, match="loopback|no hostname"):
            validate_https_url("https://[::1]/api")


class TestPrivateIPBlocking:
    """Test that private/link-local IP addresses are blocked."""

    def test_private_ip_10_rejected(self):
        with pytest.raises(URLValidationError, match="private"):
            validate_https_url("https://10.0.0.1/api")

    def test_private_ip_172_rejected(self):
        with pytest.raises(URLValidationError, match="private"):
            validate_https_url("https://172.16.0.1/api")

    def test_private_ip_192_rejected(self):
        with pytest.raises(URLValidationError, match="private"):
            validate_https_url("https://192.168.1.1/api")


class TestDNSResolution:
    """Test DNS resolution and checking of resolved addresses."""

    def test_hostname_resolving_to_private_ip_rejected(self):
        """Hostname that resolves to a private IP is blocked."""
        with patch("netbox_ssl.utils.url_validation.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [(None, None, None, None, ("10.0.0.5", 443))]
            with pytest.raises(URLValidationError, match="private"):
                validate_https_url("https://internal.corp.example.com")

    def test_hostname_resolving_to_public_ip_accepted(self):
        """Hostname resolving to a public IP passes."""
        with patch("netbox_ssl.utils.url_validation.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [(None, None, None, None, ("93.184.216.34", 443))]
            validate_https_url("https://example.com")

    def test_dns_failure_raises(self):
        """DNS resolution failure raises URLValidationError."""
        import socket

        with patch("netbox_ssl.utils.url_validation.socket.getaddrinfo") as mock_dns:
            mock_dns.side_effect = socket.gaierror("DNS lookup failed")
            with pytest.raises(URLValidationError, match="DNS resolution failed"):
                validate_https_url("https://nonexistent.invalid")


class TestEdgeCases:
    """Test edge cases in URL validation."""

    def test_url_without_hostname_rejected(self):
        with pytest.raises(URLValidationError, match="no hostname"):
            validate_https_url("https:///path")

    def test_public_literal_ip_accepted(self):
        """Public IP address as hostname is accepted."""
        validate_https_url("https://93.184.216.34/api")
