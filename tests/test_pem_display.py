"""Render tests for the public-PEM section on the certificate detail page (#113).

The public certificate PEM (``Certificate.pem_content``) is shown on the detail
page to any user with VIEW permission, in a collapsible card with copy/download
controls. These tests render the real detail view in the NetBox container and
assert the section appears when a PEM is present and is absent otherwise.

Requires a real NetBox environment (DB + templates); skipped on the host unit
lane via the find_spec guard.
"""

import contextlib
import importlib.util
import os
from datetime import datetime, timezone

import pytest

try:
    _spec = importlib.util.find_spec("netbox")
    NETBOX_AVAILABLE = _spec is not None and _spec.origin is not None
except (ValueError, ModuleNotFoundError):
    NETBOX_AVAILABLE = False

if NETBOX_AVAILABLE:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "netbox.settings")
    import django

    with contextlib.suppress(Exception):
        django.setup()

requires_netbox = pytest.mark.skipif(
    not NETBOX_AVAILABLE,
    reason="NetBox not available - run these tests inside the Docker container",
)

pytestmark = [pytest.mark.integration, pytest.mark.django_db]

SAMPLE_PEM = "-----BEGIN CERTIFICATE-----\nMIIBpemDisplayRenderTestContent\n-----END CERTIFICATE-----"


def _superuser():
    from django.contrib.auth import get_user_model

    User = get_user_model()
    user, _ = User.objects.get_or_create(
        username="test_pem_display_user",
        defaults={"is_superuser": True},
    )
    if not user.is_superuser:
        user.is_superuser = True
        user.save()
    return user


def _make_certificate(**overrides):
    from netbox_ssl.models import Certificate

    fields = {
        "common_name": "pem-display-test.example.com",
        "serial_number": "PEMDISPLAYTEST",
        "issuer": "Test CA",
        "valid_from": datetime(2025, 1, 1, tzinfo=timezone.utc),
        "valid_to": datetime(2027, 1, 1, tzinfo=timezone.utc),
        "status": "active",
        "pem_content": SAMPLE_PEM,
    }
    fields.update(overrides)
    return Certificate.objects.create(**fields)


@requires_netbox
def test_pem_section_rendered_when_pem_present():
    """A certificate with pem_content shows the PEM card + copy/download controls."""
    from django.test import Client

    cert = _make_certificate()
    try:
        client = Client()
        client.force_login(_superuser())
        resp = client.get(cert.get_absolute_url())
        assert resp.status_code == 200
        html = resp.content.decode()
        assert "Certificate PEM" in html
        assert 'id="pem-content"' in html
        assert "pem-copy-btn" in html
        assert "pem-download-btn" in html
        # The actual PEM body is rendered inside the <pre> block.
        assert "MIIBpemDisplayRenderTestContent" in html
    finally:
        cert.delete()


@requires_netbox
def test_pem_section_absent_when_no_pem():
    """A certificate without pem_content does NOT render the PEM card."""
    from django.test import Client

    cert = _make_certificate(serial_number="PEMDISPLAYNONE", pem_content="")
    try:
        client = Client()
        client.force_login(_superuser())
        resp = client.get(cert.get_absolute_url())
        assert resp.status_code == 200
        html = resp.content.decode()
        # The section is guarded by {% if object.pem_content %}.
        assert 'id="pem-content"' not in html
        assert "pem-copy-btn" not in html
    finally:
        cert.delete()
