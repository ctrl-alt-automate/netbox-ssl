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
    # (registry fallback below).
    from azure.core.exceptions import (
        ClientAuthenticationError,
        HttpResponseError,
        ResourceNotFoundError,
    )
    from azure.identity import ClientSecretCredential, DefaultAzureCredential
    from azure.keyvault.certificates import CertificateClient
except ImportError as exc:  # pragma: no cover - exercised by the registry fallback
    raise ImportError(
        "Azure Key Vault adapter requires the azure extras. Install with: pip install netbox-ssl[azure]"
    ) from exc

from .base import BaseAdapter, CredentialField, FetchedCertificate

logger = logging.getLogger("netbox_ssl.adapters")


class ProhibitedFieldError(Exception):
    """Raised when a Key Vault response carries a field that could hold key material.

    Deliberately NOT caught by fetch_certificates' per-certificate handler: this
    is a tripwire, and a tripwire that degrades to a skipped item is not a
    tripwire. If Azure ever returns key material, the sync must stop and be seen.
    """


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

    @staticmethod
    def _assert_no_prohibited_keys(obj) -> None:
        """Fail hard if a response carries a field that could hold key material.

        Azure does not return key material from the certificates API today.
        This is a tripwire for the day it changes, or the day someone widens
        the RBAC role — see PROHIBITED_SYNC_FIELDS for the canonical list.

        Deliberately raises ProhibitedFieldError, not ValueError:
        fetch_certificates' per-certificate handler catches broad exceptions
        to keep one bad certificate from failing the whole run, and a
        tripwire that gets swallowed by that handler is not a tripwire. See
        ProhibitedFieldError's docstring.

        Raises:
            ProhibitedFieldError: If any prohibited field name is present.
        """
        from .base import PROHIBITED_SYNC_FIELDS

        if isinstance(obj, dict):
            names = {str(key).lower() for key in obj}
        else:
            names = {name.lower() for name in dir(obj) if not name.startswith("_")}

        found = names & PROHIBITED_SYNC_FIELDS
        if found:
            raise ProhibitedFieldError(
                f"Azure Key Vault response contains prohibited field(s): {sorted(found)}. "
                "Refusing to process — this adapter must never handle key material."
            )

    def _to_fetched(self, kv_cert) -> FetchedCertificate | None:
        """Convert one KeyVaultCertificate into a FetchedCertificate.

        Everything X.509 knows comes from X.509: the DER bytes go through the
        plugin's own parser, which yields canonical values and keeps this
        adapter consistent with every other import path. Azure's own
        x509_thumbprint is deliberately unused — it is SHA-1.

        Returns:
            The mapped certificate, or None if it carries no public part yet.
        """
        self._assert_no_prohibited_keys(kv_cert)

        from ..utils.parser import CertificateParser

        der = getattr(kv_cert, "cer", None)
        if not der:
            logger.info(
                "Skipping Azure certificate '%s': no public certificate yet (issuance pending)",
                getattr(kv_cert, "name", "?"),
            )
            return None

        parsed = CertificateParser.parse_der(bytes(der))
        props = kv_cert.properties

        return FetchedCertificate(
            # Deliberately NOT str(props.id): Azure's own id is version-pinned
            # (".../certificates/<name>/<version>") because get_certificate()
            # always returns the latest version. Using it as external_id would
            # change on every renewal, and the sync engine's diff phase keys
            # on external_id — a renewal would look like a brand-new
            # certificate and never take the Janus renewal path. Build the
            # version-independent URI ourselves instead of trusting a shape
            # we do not control. Do not "simplify" this back to props.id.
            external_id=f"{self.source.base_url.rstrip('/')}/certificates/{props.name}",
            common_name=parsed.common_name,
            serial_number=parsed.serial_number,
            fingerprint_sha256=parsed.fingerprint_sha256,
            issuer=parsed.issuer,
            valid_from=parsed.valid_from,
            valid_to=parsed.valid_to,
            sans=tuple(parsed.sans),
            key_size=parsed.key_size,
            algorithm=parsed.algorithm,
            pem_content=parsed.pem_content,
            issuer_chain=parsed.issuer_chain,
            certificate_type=parsed.certificate_type,
            tags=self._map_tags(props),
            status=self._map_status(props, parsed.valid_to),
        )

    # Azure certificate state -> plugin Certificate.status value.
    #
    # Deliberately NOT `from ..models import CertificateStatusChoices`: a
    # sys.modules mock installed by another test file (test_analytics.py
    # setdefault's a bare MagicMock for "netbox_ssl.models" so it stays
    # importable without Django) persists for the rest of the pytest
    # session and would silently replace the real choice values here too.
    # AwsAcmAdapter hit the same constraint and solved it the same way with
    # its own _STATUS_MAP — follow that precedent rather than re-litigate it.
    # Kept honest against drift by
    # TestStatusMapping.test_status_literals_match_the_real_choice_set,
    # which checks these literals against the real ChoiceSet in the Docker
    # container lane.
    _STATUS_ARCHIVED = "archived"
    _STATUS_EXPIRED = "expired"
    _STATUS_ACTIVE = "active"

    @classmethod
    def _map_status(cls, props, valid_to) -> str:
        """Map Azure certificate state onto a plugin status.

        A disabled certificate outranks an expired one: disabling is an
        explicit operator action, while expiry is a fact about the clock.
        Expiry itself is judged on the parsed X.509 validity passed in, not
        on Azure's own `expires_on` metadata, so the two can never disagree.
        """
        from datetime import datetime, timezone

        if getattr(props, "enabled", True) is False:
            return cls._STATUS_ARCHIVED
        if valid_to and valid_to < datetime.now(timezone.utc):
            return cls._STATUS_EXPIRED
        return cls._STATUS_ACTIVE

    def _map_tags(self, props) -> tuple[str, ...]:
        """Flatten Azure's key/value tags into NetBox tag names.

        `key`/`value` becomes `key=value`; a valueless tag keeps just the key.
        Sorted so a sync run produces the same order every time. Returns empty
        unless the source opted in.
        """
        if not getattr(self.source, "sync_tags", False):
            return ()
        tags = getattr(props, "tags", None) or {}
        return tuple(sorted(f"{key}={value}" if value else str(key) for key, value in tags.items()))

    def fetch_certificates(self) -> list[FetchedCertificate]:
        """Fetch every certificate in the vault.

        A failure on one certificate is logged and skipped: one bad entry must
        never cost the operator the whole sync run.
        """
        client = self._get_client()
        results: list[FetchedCertificate] = []

        for props in client.list_properties_of_certificates():
            name = getattr(props, "name", None)
            try:
                kv_cert = client.get_certificate(name)
                fetched = self._to_fetched(kv_cert)
            except ProhibitedFieldError:
                raise
            except Exception:
                logger.exception("Skipping Azure certificate '%s': fetch failed", name)
                continue
            if fetched is not None:
                results.append(fetched)

        logger.info("Fetched %d certificate(s) from Azure Key Vault", len(results))
        return results

    def get_certificate_detail(self, external_id: str) -> FetchedCertificate | None:
        """Fetch one certificate by its vault URI.

        Accepts both the version-independent form this adapter now writes
        (".../certificates/<name>") and a version-pinned form
        (".../certificates/<name>/<version>") that may still be stored from
        an earlier run or entered by hand. The certificate name is always the
        path segment immediately after "certificates/" — never simply the
        last segment, which would be the version on a version-pinned id.

        Args:
            external_id: The vault-scoped certificate URI.

        Returns:
            The mapped certificate, or None if it is gone or has no public part.
        """
        parts = external_id.rstrip("/").split("/")
        try:
            name = parts[parts.index("certificates") + 1]
        except (ValueError, IndexError):
            name = parts[-1]
        try:
            return self._to_fetched(self._get_client().get_certificate(name))
        except ResourceNotFoundError:
            return None
