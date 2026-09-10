"""Render every plugin page and assert it returns 200.

The integration lanes exercise models, serializers and scripts, but never render
a list or detail view. Two bugs reached a live NetBox because of that gap:

* ``NetBoxTable``'s ``ActionsColumn`` reverses every action it renders, so the
  missing ``compliancecheck_edit`` view raised ``NoReverseMatch`` and 500'd the
  compliance check list plus the HTMX fragment embedding it.
* ``ObjectListView.actions`` declared as the legacy ``{name: permissions}`` dict
  worked on NetBox 4.4-4.6 through a ``LEGACY_ACTIONS`` shim, which 4.7 removed:
  iterating the dict yields strings and ``action.permissions_required`` raises
  ``AttributeError``, 500ing the same page on 4.7 only.

Neither is reachable without actually rendering the page, so these tests do. They
need the ORM and NetBox's URLconf, so they run in the container lane.
"""

from __future__ import annotations

import datetime
import os

import pytest

UTC = datetime.timezone.utc


def _make_pem(cn: str, eku: tuple[str, ...] | None = ("server",), bits: int = 2048) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(int.from_bytes(os.urandom(16), "big"))
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn.replace("*.", ""))]), critical=False)
    )
    if eku is not None:
        oids = {"server": ExtendedKeyUsageOID.SERVER_AUTH, "client": ExtendedKeyUsageOID.CLIENT_AUTH}
        builder = builder.add_extension(x509.ExtendedKeyUsage([oids[p] for p in eku]), critical=False)
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()


@pytest.fixture
def client_and_data(db):
    """A logged-in superuser plus one certificate, one policy and one check."""
    from django.test import Client
    from users.models import User

    from netbox_ssl.api.serializers import CertificateImportSerializer
    from netbox_ssl.models import ComplianceCheck, CompliancePolicy
    from netbox_ssl.utils.compliance_checker import ComplianceChecker

    user, _ = User.objects.get_or_create(username="page-rendering-test")
    user.is_superuser = True
    user.is_active = True
    user.save()

    serializer = CertificateImportSerializer(data={"pem_content": _make_pem("render.example.com")})
    assert serializer.is_valid(), serializer.errors
    certificate = serializer.save()

    policy = CompliancePolicy.objects.create(
        name="Render test min key size",
        policy_type="min_key_size",
        severity="critical",
        enabled=True,
        parameters={"min_bits": 2048},
    )
    ComplianceChecker.save_check_results(certificate, ComplianceChecker.run_all_checks(certificate, [policy]))
    check = ComplianceCheck.objects.filter(policy=policy).first()
    assert check is not None

    client = Client()
    client.force_login(user)
    return client, certificate, policy, check


@pytest.mark.django_db
class TestPagesRender:
    def test_compliance_pages_render(self, client_and_data):
        client, _certificate, policy, check = client_and_data
        pages = {
            "policy list": "/plugins/ssl/compliance-policies/",
            "policy add": "/plugins/ssl/compliance-policies/add/",
            "policy detail": f"/plugins/ssl/compliance-policies/{policy.pk}/",
            "policy edit": f"/plugins/ssl/compliance-policies/{policy.pk}/edit/",
            "check list": "/plugins/ssl/compliance-checks/",
            "check detail": f"/plugins/ssl/compliance-checks/{check.pk}/",
            "check list filtered": f"/plugins/ssl/compliance-checks/?policy_id={policy.pk}",
        }
        failures = {
            label: client.get(url, follow=True).status_code
            for label, url in pages.items()
            if client.get(url, follow=True).status_code != 200
        }
        assert not failures, f"pages did not render: {failures}"

    def test_certificate_and_assignment_pages_render(self, client_and_data):
        client, certificate, _policy, _check = client_and_data
        pages = {
            "certificate list": "/plugins/ssl/certificates/",
            "certificate detail": f"/plugins/ssl/certificates/{certificate.pk}/",
            "certificate filtered by type": "/plugins/ssl/certificates/?certificate_type=server",
            "assignment list": "/plugins/ssl/assignments/",
            "assignment list sorted by target": "/plugins/ssl/assignments/?sort=_assigned_object_name",
            "compliance report": "/plugins/ssl/compliance-report/",
            "analytics dashboard": "/plugins/ssl/analytics/",
        }
        failures = {
            label: client.get(url, follow=True).status_code
            for label, url in pages.items()
            if client.get(url, follow=True).status_code != 200
        }
        assert not failures, f"pages did not render: {failures}"

    def test_list_view_actions_are_object_action_classes(self, client_and_data):
        """Guard the 4.7 break directly: actions must not be the legacy dict.

        NetBox 4.7 iterates `ObjectListView.actions` and reads
        `action.permissions_required` on each entry. A dict yields strings.
        """
        from netbox_ssl.views import ComplianceCheckListView

        for action in ComplianceCheckListView.actions:
            assert hasattr(action, "permissions_required"), (
                f"{action!r} is not an ObjectAction class; the legacy "
                "{name: permissions} dict was removed in NetBox 4.7"
            )
