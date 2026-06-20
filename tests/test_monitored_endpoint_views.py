"""
Tests for MonitoredEndpoint CRUD views and the #149 auto-create hook in url_import.py.
"""

from __future__ import annotations

import datetime
import uuid
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


@pytest.mark.django_db
class TestCertificateDetailMonitoredEndpointsTab:
    """Certificate detail page shows the Monitored Endpoints reverse tab (#149)."""

    def _make_cert(self, uid: str):
        from django.utils import timezone

        from netbox_ssl.models import Certificate

        # Use uid bytes so each cert gets a unique fingerprint.
        uid_bytes = uid.encode()[:8].ljust(8, b"\x00")
        fingerprint = ":".join([f"{b:02X}" for b in (uid_bytes * 4)[:32]])
        return Certificate.objects.create(
            common_name=f"{uid}.example.com",
            serial_number=f"S:{uid}",
            issuer="CA",
            valid_from=timezone.now(),
            valid_to=timezone.now() + datetime.timedelta(days=90),
            fingerprint_sha256=fingerprint,
            algorithm="RSA",
        )

    def test_certificate_detail_shows_linked_endpoints(self, client, django_user_model):
        """Certificate detail page lists a MonitoredEndpoint that points to it."""
        user = django_user_model.objects.create_user("u2", password="x", is_superuser=True)
        client.force_login(user)
        uid = uuid.uuid4().hex[:8]
        cert = self._make_cert(uid)

        from netbox_ssl.models import MonitoredEndpoint

        MonitoredEndpoint.objects.create(name="hr-portal", url="https://hr.example.com", certificate=cert)

        resp = client.get(f"/plugins/ssl/certificates/{cert.pk}/")
        assert resp.status_code == 200
        assert b"hr-portal" in resp.content

    def test_certificate_detail_no_endpoints_tab_hidden(self, client, django_user_model):
        """Certificate detail page does not show the Monitored Endpoints tab when no endpoints exist."""
        user = django_user_model.objects.create_user("u3", password="x", is_superuser=True)
        client.force_login(user)
        uid = uuid.uuid4().hex[:8]
        cert = self._make_cert(uid)

        resp = client.get(f"/plugins/ssl/certificates/{cert.pk}/")
        assert resp.status_code == 200
        # Tab anchor should not be in the page
        assert b"tab-monitored-endpoints" not in resp.content

    def test_certificate_detail_multiple_endpoints(self, client, django_user_model):
        """Certificate detail page lists all MonitoredEndpoints linked to a certificate."""
        user = django_user_model.objects.create_user("u4", password="x", is_superuser=True)
        client.force_login(user)
        uid = uuid.uuid4().hex[:8]
        cert = self._make_cert(uid)

        from netbox_ssl.models import MonitoredEndpoint

        MonitoredEndpoint.objects.create(name="endpoint-alpha", url="https://alpha.example.com", certificate=cert)
        MonitoredEndpoint.objects.create(name="endpoint-beta", url="https://beta.example.com", certificate=cert)

        resp = client.get(f"/plugins/ssl/certificates/{cert.pk}/")
        assert resp.status_code == 200
        assert b"endpoint-alpha" in resp.content
        assert b"endpoint-beta" in resp.content


@pytest.mark.django_db
class TestEndpointDetailRotationHistoryTab:
    """Endpoint detail page shows the Rotation History tab (#149)."""

    def _make_cert(self, uid: str, days: int = 90):
        from django.utils import timezone

        from netbox_ssl.models import Certificate

        # Use uid bytes so each cert gets a unique fingerprint.
        uid_bytes = uid.encode()[:8].ljust(8, b"\x00")
        fingerprint = ":".join([f"{b:02X}" for b in (uid_bytes * 4)[:32]])
        return Certificate.objects.create(
            common_name=f"{uid}.example.com",
            serial_number=f"S:{uid}",
            issuer="CA",
            valid_from=timezone.now(),
            valid_to=timezone.now() + datetime.timedelta(days=days),
            fingerprint_sha256=fingerprint,
            algorithm="RSA",
        )

    def test_rotation_history_tab_renders_empty(self, client, django_user_model):
        """Endpoint detail page shows Rotation History tab even when empty."""
        user = django_user_model.objects.create_user("rh1", password="x", is_superuser=True)
        client.force_login(user)

        from netbox_ssl.models import MonitoredEndpoint

        ep = MonitoredEndpoint.objects.create(name="my-portal", url="https://portal.example.com")
        resp = client.get(f"/plugins/ssl/monitored-endpoints/{ep.pk}/")
        assert resp.status_code == 200
        assert b"Rotation History" in resp.content
        assert b"No rotation history recorded yet." in resp.content

    def test_rotation_history_tab_shows_certificate(self, client, django_user_model):
        """Endpoint detail page lists MonitoredEndpointCertificate entries in Rotation History."""
        from django.utils import timezone

        user = django_user_model.objects.create_user("rh2", password="x", is_superuser=True)
        client.force_login(user)
        uid = uuid.uuid4().hex[:8]
        cert = self._make_cert(uid)

        from netbox_ssl.models import MonitoredEndpoint, MonitoredEndpointCertificate

        ep = MonitoredEndpoint.objects.create(
            name="history-portal",
            url="https://history.example.com",
            certificate=cert,
        )
        now = timezone.now()
        MonitoredEndpointCertificate.objects.create(
            endpoint=ep,
            certificate=cert,
            first_seen=now - datetime.timedelta(days=30),
            last_seen=now,
        )

        resp = client.get(f"/plugins/ssl/monitored-endpoints/{ep.pk}/")
        assert resp.status_code == 200
        assert b"Rotation History" in resp.content
        # Certificate's common_name should appear in the history table
        assert uid.encode() in resp.content

    def test_rotation_history_shows_multiple_entries(self, client, django_user_model):
        """Endpoint detail page lists all historical certificate entries."""
        from django.utils import timezone

        user = django_user_model.objects.create_user("rh3", password="x", is_superuser=True)
        client.force_login(user)
        uid_a = uuid.uuid4().hex[:8]
        uid_b = uuid.uuid4().hex[:8]
        cert_a = self._make_cert(uid_a, days=90)
        cert_b = self._make_cert(uid_b, days=180)

        from netbox_ssl.models import MonitoredEndpoint, MonitoredEndpointCertificate

        ep = MonitoredEndpoint.objects.create(
            name="multi-history",
            url="https://multi.example.com",
            certificate=cert_b,
        )
        now = timezone.now()
        MonitoredEndpointCertificate.objects.create(
            endpoint=ep,
            certificate=cert_a,
            first_seen=now - datetime.timedelta(days=180),
            last_seen=now - datetime.timedelta(days=90),
        )
        MonitoredEndpointCertificate.objects.create(
            endpoint=ep,
            certificate=cert_b,
            first_seen=now - datetime.timedelta(days=90),
            last_seen=now,
        )

        resp = client.get(f"/plugins/ssl/monitored-endpoints/{ep.pk}/")
        assert resp.status_code == 200
        assert uid_a.encode() in resp.content
        assert uid_b.encode() in resp.content
