"""Unit tests for the shared scrape-and-import service (Task 2, #149)."""

from __future__ import annotations

import sys
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

# Add tests/ dir so cert_factory can be imported as a top-level module
# (mirrors the pattern in test_aws_acm_adapter.py).
_tests_dir = Path(__file__).parent
if str(_tests_dir) not in sys.path:
    sys.path.insert(0, str(_tests_dir))

from cert_factory import CertFactory  # noqa: E402


def _pem(cn: str | None = None) -> str:
    """Return a fresh self-signed PEM for test isolation."""
    return CertFactory.create(cn=cn or f"{uuid.uuid4().hex[:8]}.example.com")


@pytest.mark.django_db
class TestScrapeAndImport:
    """Core create / dedup behaviour of scrape_and_import."""

    @patch("netbox_ssl.utils.url_cert_import.validate_https_url")
    @patch(
        "netbox_ssl.utils.url_cert_import.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("203.0.113.10", 443))],
    )
    @patch("netbox_ssl.utils.url_cert_import.scrape_tls_certificate")
    def test_creates_certificate_on_miss(self, mock_scrape, _gai, _val):
        """First import creates the Certificate row."""
        from netbox_ssl.models import Certificate
        from netbox_ssl.utils.url_cert_import import scrape_and_import

        mock_scrape.return_value = _pem()
        before = Certificate.objects.count()
        outcome = scrape_and_import(
            "https://a.example.com", "a.example.com", 443, allowlist=[]
        )
        assert outcome.created is True
        assert Certificate.objects.count() == before + 1
        assert outcome.certificate.discovered_via_url == "https://a.example.com"

    @patch("netbox_ssl.utils.url_cert_import.validate_https_url")
    @patch(
        "netbox_ssl.utils.url_cert_import.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("203.0.113.10", 443))],
    )
    @patch("netbox_ssl.utils.url_cert_import.scrape_tls_certificate")
    def test_matches_existing_on_second_call(self, mock_scrape, _gai, _val):
        """Second call with same cert returns created=False and the same PK."""
        from netbox_ssl.models import Certificate
        from netbox_ssl.utils.url_cert_import import scrape_and_import

        pem = _pem()
        mock_scrape.return_value = pem
        first = scrape_and_import(
            "https://a.example.com", "a.example.com", 443, allowlist=[]
        )
        before = Certificate.objects.count()
        second = scrape_and_import(
            "https://a.example.com", "a.example.com", 443, allowlist=[]
        )
        assert second.created is False
        assert second.certificate.pk == first.certificate.pk
        assert Certificate.objects.count() == before

    @patch("netbox_ssl.utils.url_cert_import.validate_https_url")
    @patch(
        "netbox_ssl.utils.url_cert_import.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("203.0.113.10", 443))],
    )
    @patch("netbox_ssl.utils.url_cert_import.scrape_tls_certificate")
    def test_set_discovered_url_false_leaves_field_empty(self, mock_scrape, _gai, _val):
        """When set_discovered_url=False the field is not written."""
        from netbox_ssl.utils.url_cert_import import scrape_and_import

        mock_scrape.return_value = _pem()
        outcome = scrape_and_import(
            "https://b.example.com",
            "b.example.com",
            443,
            allowlist=[],
            set_discovered_url=False,
        )
        assert outcome.created is True
        assert outcome.certificate.discovered_via_url == ""

    @patch("netbox_ssl.utils.url_cert_import.validate_https_url")
    @patch("netbox_ssl.utils.url_cert_import.socket.getaddrinfo", side_effect=OSError("Name or service not known"))
    def test_dns_failure_raises_tls_scrape_error(self, _gai, _val):
        """DNS OSError from getaddrinfo must surface as TLSScrapeError (not bare OSError)."""
        from netbox_ssl.utils.tls_scraper import TLSScrapeError
        from netbox_ssl.utils.url_cert_import import scrape_and_import

        with pytest.raises(TLSScrapeError, match="DNS failed"):
            scrape_and_import(
                "https://no-such-host.example.com",
                "no-such-host.example.com",
                443,
                allowlist=[],
            )


@pytest.mark.django_db
class TestProcessRowParity:
    """#106 parity: _process_row must return the documented outcome dict shapes."""

    @patch("netbox_ssl.utils.url_cert_import.validate_https_url")
    @patch(
        "netbox_ssl.utils.url_cert_import.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("203.0.113.10", 443))],
    )
    @patch("netbox_ssl.utils.url_cert_import.scrape_tls_certificate")
    def test_imported_outcome_shape(self, mock_scrape, _gai, _val):
        """_process_row returns {'status': 'imported', 'url': ..., 'detail': CN, 'pk': id}."""
        from netbox_ssl.views.url_import import UrlImportView

        cn = "import-shape.example.com"
        mock_scrape.return_value = _pem(cn=cn)
        view = UrlImportView()
        row = {
            "url": "https://c.example.com",
            "host": "c.example.com",
            "port": 443,
            "sni": None,
            "verify_chain": True,
            "tenant": None,
        }
        result = view._process_row(None, row, [], [], None)
        assert result["status"] == "imported"
        assert result["url"] == "https://c.example.com"
        assert result["detail"] == cn
        assert "pk" in result

    @patch("netbox_ssl.utils.url_cert_import.validate_https_url")
    @patch(
        "netbox_ssl.utils.url_cert_import.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("203.0.113.10", 443))],
    )
    @patch("netbox_ssl.utils.url_cert_import.scrape_tls_certificate")
    def test_matched_outcome_shape(self, mock_scrape, _gai, _val):
        """Second call with same cert returns {'status': 'matched', 'pk': ...}."""
        from netbox_ssl.views.url_import import UrlImportView

        pem_cn = "matched-shape.example.com"
        pem = _pem(cn=pem_cn)
        mock_scrape.return_value = pem
        view = UrlImportView()
        row = {
            "url": "https://d.example.com",
            "host": "d.example.com",
            "port": 443,
            "sni": None,
            "verify_chain": True,
            "tenant": None,
        }
        view._process_row(None, row, [], [], None)
        result = view._process_row(None, row, [], [], None)
        assert result["status"] == "matched"
        assert "pk" in result
        assert result["detail"] == pem_cn

    @patch("netbox_ssl.utils.url_cert_import.validate_https_url")
    @patch(
        "netbox_ssl.utils.url_cert_import.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("203.0.113.10", 443))],
    )
    @patch("netbox_ssl.utils.url_cert_import.scrape_tls_certificate")
    def test_blocked_outcome_shape(self, mock_scrape, _gai, mock_val):
        """URLValidationError maps to {'status': 'blocked'}."""
        from netbox_ssl.utils.url_validation import URLValidationError
        from netbox_ssl.views.url_import import UrlImportView

        mock_val.side_effect = URLValidationError("blocked")
        view = UrlImportView()
        row = {
            "url": "https://10.0.0.1",
            "host": "10.0.0.1",
            "port": 443,
            "sni": None,
            "verify_chain": True,
            "tenant": None,
        }
        result = view._process_row(None, row, [], [], None)
        assert result["status"] == "blocked"
        assert result["url"] == "https://10.0.0.1"

    @patch("netbox_ssl.utils.url_cert_import.validate_https_url")
    @patch(
        "netbox_ssl.utils.url_cert_import.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("203.0.113.10", 443))],
    )
    @patch("netbox_ssl.utils.url_cert_import.scrape_tls_certificate")
    def test_unreachable_outcome_shape(self, mock_scrape, _gai, _val):
        """TLSScrapeError maps to {'status': 'unreachable'}."""
        from netbox_ssl.utils.tls_scraper import TLSScrapeError
        from netbox_ssl.views.url_import import UrlImportView

        mock_scrape.side_effect = TLSScrapeError("timeout")
        view = UrlImportView()
        row = {
            "url": "https://e.example.com",
            "host": "e.example.com",
            "port": 443,
            "sni": None,
            "verify_chain": True,
            "tenant": None,
        }
        result = view._process_row(None, row, [], [], None)
        assert result["status"] == "unreachable"

    @patch("netbox_ssl.utils.url_cert_import.validate_https_url")
    @patch(
        "netbox_ssl.utils.url_cert_import.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("203.0.113.10", 443))],
    )
    @patch("netbox_ssl.utils.url_cert_import.scrape_tls_certificate")
    def test_imported_untrusted_when_verify_chain_false(self, mock_scrape, _gai, _val):
        """verify_chain=False yields {'status': 'imported_untrusted'}."""
        from netbox_ssl.views.url_import import UrlImportView

        mock_scrape.return_value = _pem()
        view = UrlImportView()
        row = {
            "url": "https://f.example.com",
            "host": "f.example.com",
            "port": 443,
            "sni": None,
            "verify_chain": False,
            "tenant": None,
        }
        result = view._process_row(None, row, [], [], None)
        assert result["status"] == "imported_untrusted"
