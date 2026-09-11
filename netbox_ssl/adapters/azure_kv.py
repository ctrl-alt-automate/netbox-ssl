"""Read-only adapter for Azure Key Vault (#101).

Lists certificates in one vault and returns their public metadata. Like the AWS
ACM adapter, it uses a vendor SDK directly rather than BaseAdapter's HTTP
helpers, so the base class's response-size cap and redirect blocking do not
apply — §6.2 of the design compensates with vault-hostname validation.

Never constructs SecretClient or KeyClient. A certificate response carries `kid`
and `sid`, references to the key and to the secret holding the full PFX; both are
metadata and are never dereferenced. The documented minimum RBAC role,
`Key Vault Reader`, cannot follow them either.
"""

from __future__ import annotations

import logging

try:
    # Unused for now — the try/except here is an availability probe for the
    # optional azure extras (registry fallback below). Tasks 5-8 add the
    # method bodies that use these names.
    from azure.core.exceptions import (  # noqa: F401
        ClientAuthenticationError,
        HttpResponseError,
        ResourceNotFoundError,
    )
    from azure.identity import ClientSecretCredential, DefaultAzureCredential  # noqa: F401
    from azure.keyvault.certificates import CertificateClient  # noqa: F401
except ImportError as exc:  # pragma: no cover - exercised by the registry fallback
    raise ImportError(
        "Azure Key Vault adapter requires the azure extras. Install with: pip install netbox-ssl[azure]"
    ) from exc

from .base import BaseAdapter, CredentialField, FetchedCertificate

logger = logging.getLogger("netbox_ssl.adapters")

# Accepted Key Vault hostname suffixes, per design §6.2. The SDK bypasses
# BaseAdapter._make_request, so this is the adapter's own SSRF guard.
VAULT_HOST_SUFFIXES: tuple[str, ...] = (
    ".vault.azure.net",  # global
    ".vault.azure.cn",  # China
    ".vault.usgovcloudapi.net",  # US Government
    ".vault.microsoftazure.de",  # Germany
)


class AzureKvAdapter(BaseAdapter):
    """Read-only adapter for Azure Key Vault certificates.

    Supports two auth methods:
    - azure_managed_identity: DefaultAzureCredential — resolves managed
      identity, workload identity (GitHub OIDC) and a local `az login`.
    - azure_explicit: operator-supplied tenant_id + client_id + client_secret.

    One ExternalSource = one vault, matching Azure's own model and the
    one-source-per-endpoint convention of the other adapters.
    """

    SUPPORTED_AUTH_METHODS: tuple[str, ...] = ("azure_managed_identity", "azure_explicit")
    IMPLICIT_AUTH_METHODS: tuple[str, ...] = ("azure_managed_identity",)
    REQUIRES_BASE_URL: bool = True
    REQUIRES_REGION: bool = False

    @classmethod
    def credential_schema(cls, auth_method: str) -> dict[str, CredentialField]:
        """Return the credential component schema for a given auth_method."""
        if auth_method == "azure_managed_identity":
            return {}
        if auth_method == "azure_explicit":
            return {
                "tenant_id": CredentialField(
                    required=True,
                    label="Tenant ID",
                    secret=False,
                    help_text="Entra ID (Azure AD) tenant GUID",
                ),
                "client_id": CredentialField(
                    required=True,
                    label="Client ID",
                    secret=False,
                    help_text="Application (client) ID of the service principal",
                ),
                "client_secret": CredentialField(
                    required=True,
                    label="Client Secret",
                    secret=True,
                    help_text="Service principal secret (env-var reference recommended)",
                ),
            }
        raise ValueError(
            f"AzureKvAdapter does not support auth_method '{auth_method}'. "
            f"Supported: {list(cls.SUPPORTED_AUTH_METHODS)}"
        )

    def __init__(self, source) -> None:
        super().__init__(source)
        self._client = None  # lazy: built on first use by _get_client()

    def test_connection(self) -> tuple[bool, str]:
        """Placeholder — implemented in Task 5."""
        raise NotImplementedError

    def fetch_certificates(self) -> list[FetchedCertificate]:
        """Placeholder — implemented in Task 6."""
        raise NotImplementedError

    def get_certificate_detail(self, external_id: str) -> FetchedCertificate | None:
        """Placeholder — implemented in Task 6."""
        raise NotImplementedError
