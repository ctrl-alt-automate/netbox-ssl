"""Live tests against the provisioned Azure Key Vault.

Maintainer-only: the federated credential is scoped to refs/heads/main, so these
cannot run on a pull request. Locally they run after `az login`.

Vault and certificate names come from azure-testresources-overdracht.md.

Privilege canary gating
------------------------
``test_private_key_is_unreachable`` asserts that ``SecretClient.get_secret()``
is refused with 403. That assertion is only meaningful when the identity under
test is the least-privileged one (``Key Vault Reader``). Locally, `az login`
authenticates as the maintainer's own account, which holds `Key Vault
Administrator` on this vault for day-to-day operations — `DefaultAzureCredential`
picks that up, and `get_secret()` would succeed. A 200 in that situation proves
nothing about the CI identity's role, so the canary only runs when
``AZURE_KV_LEAST_PRIVILEGE_IDENTITY=1`` is set explicitly.

This is a deliberate, explicit declaration rather than auto-detection: an
earlier version of this gate tried to infer "running as the CI service
principal" from ``GITHUB_ACTIONS`` + ``AZURE_CLIENT_ID`` being set, on the
assumption that ``azure/login@v2`` exports ``AZURE_CLIENT_ID`` into the job
environment for ``DefaultAzureCredential`` to pick up. It does not — the
action's bundled source never calls ``exportVariable`` with that name; it
only feeds ``client-id``/``tenant-id``/``subscription-id`` to `az login`
internally, so `DefaultAzureCredential` actually authenticates via
`AzureCliCredential` reading the `az` CLI's own session. That auto-detection
was always false in CI, so the canary skipped there forever, silently. The
azure-integration.yml workflow's "Live adapter tests" step now sets
``AZURE_KV_LEAST_PRIVILEGE_IDENTITY: "1"`` explicitly in its ``env:``, backed
by a documented, verified role assignment (`Key Vault Reader` only, nothing
wider) — see the comment there. ``tests/test_azure_integration_workflow.py``
guards against that declaration being silently removed later.

If the canary DOES run and the secret is readable (200), that is a genuine
stop-and-report condition: the role has been widened beyond `Key Vault Reader`.
"""

import importlib.util
import os
import sys
from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.azure_live

# Importing the adapter pulls netbox_ssl/__init__.py, which imports
# netbox.plugins, and fetch_certificates() pulls in netbox_ssl.utils (via
# ..utils.parser), whose __init__ imports assignments.py, which needs
# django.contrib.contenttypes registered. Neither the host lane nor the
# azure-integration.yml workflow installs a real NetBox, so mock netbox --
# the repo's established pattern (see test_azure_kv_adapter.py). The find_spec
# guard means the mock never replaces a real NetBox inside the Docker
# container, where this file is not expected to run anyway (it targets the
# live vault, not a NetBox instance). The Django settings bootstrap itself is
# deferred to the `adapter` fixture below (not done here at module scope) so
# that merely collecting this file -- which the host lane's
# `--collect-only` step does on every Python version -- never mutates global
# Django state for other test modules in the same session.
try:
    _spec = importlib.util.find_spec("netbox")
    _NETBOX_AVAILABLE = _spec is not None and _spec.origin is not None
except (ValueError, ModuleNotFoundError):
    _NETBOX_AVAILABLE = False

if not _NETBOX_AVAILABLE and "netbox" not in sys.modules:
    sys.modules["netbox"] = MagicMock()
    sys.modules["netbox.plugins"] = MagicMock()

VAULT_URL = os.environ.get("AZURE_TEST_VAULT_URL", "https://kv-nbssl-test-2609.vault.azure.net/")
EXPECTED_CERTS = {"test-webserver", "test-api-gateway", "test-bijna-verlopen"}


def _bootstrap_django_if_needed() -> None:
    """Configure minimal Django settings, once, only when a live test actually runs.

    `fetch_certificates()` transitively imports `netbox_ssl.utils`, whose
    package `__init__` eagerly imports `assignments.py`, which needs
    `django.contrib.contenttypes` registered (see the module-scope comment
    above). `settings.configure()` raises if settings are already configured
    -- guard on `settings.configured` so this is idempotent and so it does
    nothing in the in-container lane, which has `DJANGO_SETTINGS_MODULE`
    already loaded with a real NetBox settings module.
    """
    from django.conf import settings

    if settings.configured:
        return

    import django

    settings.configure(
        USE_TZ=True,
        TIME_ZONE="UTC",
        DATABASES={},
        INSTALLED_APPS=["django.contrib.contenttypes"],
        DEFAULT_AUTO_FIELD="django.db.models.BigAutoField",
    )
    django.setup()


def _least_privilege_identity_reason() -> str | None:
    """Return why the current identity is NOT known to be least-privileged, or None.

    None means the canary is safe to run: whatever `DefaultAzureCredential`
    resolves to is expected to be the `Key Vault Reader` CI service principal,
    not the maintainer's own (more privileged) account.

    Gates on `AZURE_KV_LEAST_PRIVILEGE_IDENTITY=1` only -- an explicit
    declaration, set by the azure-integration.yml workflow's "Live adapter
    tests" step (see the module docstring for why auto-detecting the CI
    identity from `azure/login@v2`'s environment does not work).
    """
    if os.environ.get("AZURE_KV_LEAST_PRIVILEGE_IDENTITY") == "1":
        return None
    return (
        "skipped: the identity under test is not known to be least-privileged. "
        "Local `az login` authenticates as the maintainer's own account "
        "(accounts@tcb-infra.eu), which holds Key Vault Administrator on this "
        "vault -- DefaultAzureCredential would pick that up and get_secret() "
        "would succeed, proving nothing about the CI identity's Key Vault Reader "
        "role. Set AZURE_KV_LEAST_PRIVILEGE_IDENTITY=1 to opt in explicitly (e.g. "
        "after logging in as a Key-Vault-Reader-only principal, or in CI where "
        "azure-integration.yml's 'Live adapter tests' step declares it "
        "explicitly -- there is no reliable way to auto-detect the CI identity "
        "from azure/login@v2's environment, see the module docstring)."
    )


def _live_source():
    source = MagicMock()
    source.base_url = VAULT_URL
    source.auth_method = "azure_managed_identity"
    source.auth_credentials = {}
    source.sync_tags = True
    source.name = "azure-live-test"
    return source


@pytest.fixture(scope="module")
def adapter():
    pytest.importorskip("azure.keyvault.certificates")
    _bootstrap_django_if_needed()
    from netbox_ssl.adapters.azure_kv import AzureKvAdapter

    return AzureKvAdapter(_live_source())


def test_connection_succeeds(adapter):
    ok, message = adapter.test_connection()
    assert ok, message


def test_lists_the_three_provisioned_certificates(adapter):
    names = {c.external_id.rstrip("/").split("/")[-1] for c in adapter.fetch_certificates()}
    assert EXPECTED_CERTS.issubset(names), f"missing: {EXPECTED_CERTS - names}"


def test_public_certificate_is_readable_with_key_vault_reader(adapter):
    """Proves the documented minimum role is sufficient -- the design's §2.1."""
    fetched = adapter.fetch_certificates()
    assert fetched, "no certificates returned"
    for cert in fetched:
        assert cert.pem_content.startswith("-----BEGIN CERTIFICATE-----")
        assert ":" in cert.fingerprint_sha256


def test_private_key_is_unreachable():
    """The privilege canary.

    Key Vault stores the PFX -- certificate *and* private key -- as a secret.
    `Key Vault Reader` grants secrets/readMetadata but not secrets/getSecret, so
    this must be refused. If someone widens the role to `Key Vault Certificate
    User`, this test fails loudly instead of the blast radius quietly growing.

    The adapter itself never constructs a SecretClient; this test does, to
    verify the platform-level guarantee rather than our own restraint.

    Skipped unless the identity under test is known to be least-privileged --
    see the module docstring. A 200 locally (maintainer's own, more privileged
    account) is expected and not a finding; a 200 under the gated identity is.
    """
    reason = _least_privilege_identity_reason()
    if reason:
        pytest.skip(reason)

    pytest.importorskip("azure.keyvault.secrets")

    from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
    from azure.identity import DefaultAzureCredential
    from azure.keyvault.secrets import SecretClient

    client = SecretClient(vault_url=VAULT_URL, credential=DefaultAzureCredential())
    with pytest.raises((HttpResponseError, ClientAuthenticationError)) as exc_info:
        client.get_secret("test-webserver")

    status = getattr(exc_info.value, "status_code", None)
    assert status == 403, (
        f"expected 403 Forbidden, got {status}. The identity may have been granted "
        "'Key Vault Certificate User', which allows private-key export."
    )
