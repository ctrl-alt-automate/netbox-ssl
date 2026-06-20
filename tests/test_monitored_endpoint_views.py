"""
Tests for MonitoredEndpoint CRUD views and the #149 auto-create hook in url_import.py.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


@pytest.mark.django_db
class TestMonitoredEndpointViews:
    """Tests for MonitoredEndpoint list/detail views."""

    def test_list_requires_login(self, client):
        """Anonymous GET should redirect to login (302) or return 403."""
        resp = client.get("/plugins/ssl/monitored-endpoints/")
        assert resp.status_code in (302, 403)

    def test_list_renders_for_superuser(self, client, django_user_model):
        """Superuser GET should return 200 with the endpoint name in the response."""
        user = django_user_model.objects.create_user("u", password="x", is_superuser=True)
        client.force_login(user)
        from netbox_ssl.models import MonitoredEndpoint

        MonitoredEndpoint.objects.create(name="hr", url="https://hr.example.com")
        resp = client.get("/plugins/ssl/monitored-endpoints/")
        assert resp.status_code == 200
        assert b"hr" in resp.content

    def test_add_view_requires_login(self, client):
        """Anonymous GET to add view should redirect."""
        resp = client.get("/plugins/ssl/monitored-endpoints/add/")
        assert resp.status_code in (302, 403)

    def test_add_view_renders_for_superuser(self, client, django_user_model):
        """Superuser GET to add view should return 200."""
        user = django_user_model.objects.create_user("su2", password="x", is_superuser=True)
        client.force_login(user)
        resp = client.get("/plugins/ssl/monitored-endpoints/add/")
        assert resp.status_code == 200

    def test_detail_view_renders(self, client, django_user_model):
        """Superuser can view the detail page for a monitored endpoint."""
        user = django_user_model.objects.create_user("su3", password="x", is_superuser=True)
        client.force_login(user)
        from netbox_ssl.models import MonitoredEndpoint

        ep = MonitoredEndpoint.objects.create(name="payments", url="https://pay.example.com")
        resp = client.get(f"/plugins/ssl/monitored-endpoints/{ep.pk}/")
        assert resp.status_code == 200
        assert b"payments" in resp.content

    def test_import_view_requires_login(self, client):
        """Anonymous GET to import view should redirect."""
        resp = client.get("/plugins/ssl/monitored-endpoints/import/")
        assert resp.status_code in (302, 403)

    def test_import_view_get_renders(self, client, django_user_model):
        """Superuser GET to import view renders input form."""
        user = django_user_model.objects.create_user("su4", password="x", is_superuser=True)
        client.force_login(user)
        resp = client.get("/plugins/ssl/monitored-endpoints/import/")
        assert resp.status_code == 200


@pytest.mark.django_db
class TestMonitoredEndpointImportViewPermission:
    """Security fix: bulk-import POST must be gated on add_monitoredendpoint."""

    def test_import_post_denied_without_perm(self, client, django_user_model):
        """Non-superuser without add_monitoredendpoint cannot create via import POST."""
        user = django_user_model.objects.create_user("noperm", password="x", is_superuser=False)
        client.force_login(user)
        resp = client.post(
            "/plugins/ssl/monitored-endpoints/import/",
            data={"csv_text": "url\nhttps://blocked.example.com"},
        )
        # Must redirect (not 200/create)
        assert resp.status_code == 302

        from netbox_ssl.models import MonitoredEndpoint

        assert not MonitoredEndpoint.objects.filter(url__contains="blocked.example.com").exists()


@pytest.mark.django_db
class TestMonitoredEndpointHttpsEnforcement:
    """Security fix: javascript: and http: URLs must be rejected at form and model level."""

    def test_form_rejects_javascript_uri(self):
        """MonitoredEndpointForm.clean_url must raise on javascript: URI."""
        from netbox_ssl.forms import MonitoredEndpointForm

        form = MonitoredEndpointForm(data={"name": "evil", "url": "javascript:alert(1)"})
        assert not form.is_valid()
        assert "url" in form.errors

    def test_form_rejects_http_url(self):
        """MonitoredEndpointForm.clean_url must raise on plain http:// URL."""
        from netbox_ssl.forms import MonitoredEndpointForm

        form = MonitoredEndpointForm(data={"name": "plain", "url": "http://example.com"})
        assert not form.is_valid()
        assert "url" in form.errors

    def test_form_accepts_https_url(self):
        """MonitoredEndpointForm.clean_url must accept a valid https:// URL."""
        from netbox_ssl.forms import MonitoredEndpointForm

        form = MonitoredEndpointForm(data={"name": "ok", "url": "https://secure.example.com"})
        # The url field itself should not error; other fields (tags etc.) may be absent but url is fine
        assert "url" not in form.errors

    def test_model_clean_rejects_javascript_uri(self):
        """MonitoredEndpoint.clean() must raise ValidationError on javascript: URI."""
        from django.core.exceptions import ValidationError

        from netbox_ssl.models import MonitoredEndpoint

        ep = MonitoredEndpoint(name="evil", url="javascript:alert(1)")
        with pytest.raises(ValidationError):
            ep.clean()

    def test_model_clean_rejects_http_url(self):
        """MonitoredEndpoint.clean() must raise ValidationError on http:// URL."""
        from django.core.exceptions import ValidationError

        from netbox_ssl.models import MonitoredEndpoint

        ep = MonitoredEndpoint(name="plain", url="http://example.com")
        with pytest.raises(ValidationError):
            ep.clean()

    def test_model_clean_accepts_https_url(self):
        """MonitoredEndpoint.clean() must not raise on a valid https:// URL."""
        from netbox_ssl.models import MonitoredEndpoint

        ep = MonitoredEndpoint(name="ok", url="https://secure.example.com")
        ep.clean()  # Should not raise


@pytest.mark.django_db
class TestAutoCreateHook:
    """Test the #149 auto-create hook in url_import._process_row."""

    def _make_outcome(self, url: str, common_name: str = "test.example.com"):
        """Create a fake scrape_and_import outcome."""
        from netbox_ssl.models import Certificate

        cert = Certificate.objects.create(
            common_name=common_name,
            serial_number="AABBCC",
            issuer="Test CA",
            valid_from="2025-01-01T00:00:00Z",
            valid_to="2026-01-01T00:00:00Z",
            fingerprint_sha256="AA:BB:CC",
            algorithm="RSA",
        )
        outcome = MagicMock()
        outcome.created = True
        outcome.certificate = cert
        return outcome

    def test_process_row_creates_monitored_endpoint(self, client, django_user_model):
        """When _process_row succeeds with status 'imported', a MonitoredEndpoint is upserted."""
        user = django_user_model.objects.create_user("su5", password="x", is_superuser=True)
        url = "https://import.example.com:443"
        row = {
            "row": 1,
            "url": url,
            "host": "import.example.com",
            "port": 443,
            "sni": "import.example.com",
            "verify_chain": True,
            "assigned_device": "",
            "assigned_vm": "",
            "assigned_service": "",
            "tenant": "",
        }
        outcome = self._make_outcome(url)

        request = MagicMock()
        request.user = user

        from tenancy.models import Tenant

        user_tenants = Tenant.objects.none()

        with patch("netbox_ssl.views.url_import.scrape_and_import", return_value=outcome):
            from netbox_ssl.views.url_import import UrlImportView

            view = UrlImportView()
            result = view._process_row(request, row, allowlist=[], user_tenants=user_tenants, default_tenant=None)

        assert result["status"] in ("imported", "imported_untrusted")

        from netbox_ssl.models import MonitoredEndpoint

        assert MonitoredEndpoint.objects.filter(url=url).exists()
        ep = MonitoredEndpoint.objects.get(url=url)
        assert ep.certificate == outcome.certificate
        assert ep.status == "ok"

    def test_process_row_upserts_existing_endpoint(self, client, django_user_model):
        """When the MonitoredEndpoint already exists, update_or_create updates it."""
        user = django_user_model.objects.create_user("su6", password="x", is_superuser=True)
        url = "https://upsert.example.com:443"

        from netbox_ssl.models import MonitoredEndpoint

        existing = MonitoredEndpoint.objects.create(name="old-name", url=url)

        row = {
            "row": 1,
            "url": url,
            "host": "upsert.example.com",
            "port": 443,
            "sni": "upsert.example.com",
            "verify_chain": True,
            "assigned_device": "",
            "assigned_vm": "",
            "assigned_service": "",
            "tenant": "",
        }
        outcome = self._make_outcome(url, common_name="upsert.example.com")

        request = MagicMock()
        request.user = user

        from tenancy.models import Tenant

        user_tenants = Tenant.objects.none()

        with patch("netbox_ssl.views.url_import.scrape_and_import", return_value=outcome):
            from netbox_ssl.views.url_import import UrlImportView

            view = UrlImportView()
            view._process_row(request, row, allowlist=[], user_tenants=user_tenants, default_tenant=None)

        # Still only one endpoint for this URL.
        assert MonitoredEndpoint.objects.filter(url=url).count() == 1
        existing.refresh_from_db()
        assert existing.certificate == outcome.certificate

    def test_process_row_no_endpoint_on_error(self, client, django_user_model):
        """When scrape fails, no MonitoredEndpoint is created."""
        from netbox_ssl.utils.tls_scraper import TLSScrapeError

        user = django_user_model.objects.create_user("su7", password="x", is_superuser=True)
        url = "https://unreachable.example.com:443"
        row = {
            "row": 1,
            "url": url,
            "host": "unreachable.example.com",
            "port": 443,
            "sni": "unreachable.example.com",
            "verify_chain": True,
            "assigned_device": "",
            "assigned_vm": "",
            "assigned_service": "",
            "tenant": "",
        }

        request = MagicMock()
        request.user = user

        from tenancy.models import Tenant

        user_tenants = Tenant.objects.none()

        with patch("netbox_ssl.views.url_import.scrape_and_import", side_effect=TLSScrapeError("timeout")):
            from netbox_ssl.views.url_import import UrlImportView

            view = UrlImportView()
            result = view._process_row(request, row, allowlist=[], user_tenants=user_tenants, default_tenant=None)

        assert result["status"] == "unreachable"

        from netbox_ssl.models import MonitoredEndpoint

        assert not MonitoredEndpoint.objects.filter(url=url).exists()
