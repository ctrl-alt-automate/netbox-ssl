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
    # This try/except is an availability probe for the optional azure extras
    # (registry fallback below). ResourceNotFoundError is unused until Task 6
    # adds get_certificate_detail().
    from azure.core.exceptions import (
        ClientAuthenticationError,
        HttpResponseError,
        ResourceNotFoundError,  # noqa: F401
    )
    from azure.identity import ClientSecretCredential, DefaultAzureCredential
    from azure.keyvault.certificates import CertificateClient
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

    @staticmethod
    def _validate_vault_url(url: str) -> None:
        """Reject anything that is not an HTTPS Key Vault endpoint.

        The Azure SDK issues its own requests, so BaseAdapter's guards never
        see this URL. Matching on the host's suffix keeps the adapter from
        being aimed at an arbitrary server.

        Raises:
            ValueError: If the scheme is not https or the host is not a vault.
        """
        from urllib.parse import urlparse

        parsed = urlparse(url or "")
        if parsed.scheme != "https":
            raise ValueError(f"Key Vault URL must use https, got '{parsed.scheme or 'no scheme'}'")
        host = (parsed.hostname or "").lower()
        if not any(host.endswith(suffix) for suffix in VAULT_HOST_SUFFIXES):
            raise ValueError(
                f"'{host}' is not an Azure Key Vault hostname. Expected one of: {', '.join(VAULT_HOST_SUFFIXES)}"
            )

    def _build_credential(self):
        """Build the Azure credential for this source's auth method.

        azure_managed_identity uses DefaultAzureCredential, which resolves a
        managed identity, a federated workload identity (GitHub OIDC) or a
        local `az login` — one code path for server, CI and laptop.
        """
        if self.source.auth_method == "azure_managed_identity":
            return DefaultAzureCredential()

        creds = self.resolve_credentials()
        return ClientSecretCredential(
            tenant_id=creds["tenant_id"],
            client_id=creds["client_id"],
            client_secret=creds["client_secret"],
        )

    def _get_client(self):
        """Lazily build and cache the CertificateClient.

        Only ever a CertificateClient: see the module docstring.
        """
        if self._client is None:
            self._validate_vault_url(self.source.base_url)
            self._client = CertificateClient(
                vault_url=self.source.base_url,
                credential=self._build_credential(),
            )
        return self._client

    def test_connection(self) -> tuple[bool, str]:
        """Probe the vault by listing certificate properties.

        Returns:
            (success, message). The message is safe to display: it never
            contains credential material.
        """
        try:
            count = sum(1 for _ in self._get_client().list_properties_of_certificates())
        except ClientAuthenticationError:
            logger.warning("Azure Key Vault authentication failed for source '%s'", self.source.name)
            return False, "Azure authentication failed. Check the credentials or the managed identity."
        except HttpResponseError as exc:
            if getattr(exc, "status_code", None) == 403:
                return False, (
                    "Access denied by Azure. The identity needs the 'Key Vault Reader' role "
                    "on the vault (or its resource group)."
                )
            logger.warning("Azure Key Vault error for source '%s': %s", self.source.name, exc.__class__.__name__)
            return False, "Azure Key Vault returned an error. Check the vault URL and try again."
        except ValueError as exc:
            return False, str(exc)
        except Exception:
            logger.exception("Unexpected error testing Azure Key Vault source '%s'", self.source.name)
            return False, "Unexpected error contacting Azure Key Vault."
        return True, f"Connected. {count} certificate(s) visible in the vault."

    def fetch_certificates(self) -> list[FetchedCertificate]:
        """Placeholder — implemented in Task 6."""
        raise NotImplementedError

    def get_certificate_detail(self, external_id: str) -> FetchedCertificate | None:
        """Placeholder — implemented in Task 6."""
        raise NotImplementedError
