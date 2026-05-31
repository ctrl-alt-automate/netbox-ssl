"""
Integration tests for Certificate contact-assignment support (#128).

ContactsMixin gives Certificate a contacts tab + sub-page, backed by NetBox's
tenancy.ContactAssignment. The model-level facts are covered by host unit tests
in test_models.py (TestCertificateContacts); these tests guard the URL wiring
(the one non-automatic part — the plugin hand-routes feature views) and the
end-to-end assign → read-back path. They require a real NetBox DB and run in the
Docker integration job.
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

pytestmark = pytest.mark.integration


def _make_certificate(serial="CONTACTS-IT"):
    from netbox_ssl.models import Certificate

    return Certificate.objects.create(
        common_name="contacts-it.example.com",
        serial_number=serial,
        issuer="Test CA",
        valid_from=datetime(2025, 1, 1, tzinfo=timezone.utc),
        valid_to=datetime(2027, 1, 1, tzinfo=timezone.utc),
        status="active",
    )


@requires_netbox
def test_contacts_url_reverses():
    """The hand-wired certificate_contacts route resolves (guards the URL gap)."""
    from django.urls import reverse

    url = reverse("plugins:netbox_ssl:certificate_contacts", args=[1])
    assert url.endswith("/certificates/1/contacts/")


@requires_netbox
def test_detail_page_shows_contacts_tab():
    """The certificate detail page renders the auto-registered Contacts tab."""
    from django.contrib.auth import get_user_model
    from django.test import Client

    User = get_user_model()
    user, _ = User.objects.get_or_create(username="contacts_it_user", defaults={"is_superuser": True})
    if not user.is_superuser:
        user.is_superuser = True
        user.save()

    cert = _make_certificate()
    try:
        client = Client()
        client.force_login(user)
        resp = client.get(cert.get_absolute_url())
        assert resp.status_code == 200
        # The Contacts tab links to the contacts sub-page.
        assert f"/certificates/{cert.pk}/contacts/" in resp.content.decode()
    finally:
        cert.delete()


@requires_netbox
def test_assign_and_read_back_contact():
    """A ContactAssignment to a Certificate is returned by get_contacts()."""
    from django.contrib.contenttypes.models import ContentType
    from tenancy.models import Contact, ContactAssignment, ContactRole

    from netbox_ssl.models import Certificate

    cert = _make_certificate(serial="CONTACTS-IT-RB")
    role, _ = ContactRole.objects.get_or_create(name="Technical", slug="technical")
    contact, _ = Contact.objects.get_or_create(name="Jane Ops")
    assignment = ContactAssignment.objects.create(
        object_type=ContentType.objects.get_for_model(Certificate),
        object_id=cert.pk,
        contact=contact,
        role=role,
    )
    try:
        contacts = cert.get_contacts()
        assert contacts.count() == 1
        assert contacts.first().contact.name == "Jane Ops"
    finally:
        assignment.delete()
        cert.delete()
