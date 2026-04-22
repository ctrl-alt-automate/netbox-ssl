"""AWS Certificate Manager (ACM) adapter — read-only ingestion of cert metadata.

Requires the `[aws]` optional extras: `pip install netbox-ssl[aws]`.

Architecturally diverges from Lemur/GenericREST: uses boto3 directly instead of
`requests` via `BaseAdapter._make_request()`. Reuses Phase 1 multi-credential
infrastructure for credential resolution, schema validation, and snapshot
redaction.

Design spec: docs/superpowers/specs/2026-04-22-aws-acm-adapter-design.md
"""

from __future__ import annotations

import logging

try:
    import boto3
    import botocore.exceptions  # noqa: F401 — used in error handling (Task 14)
except ImportError as exc:  # pragma: no cover — covered by lazy registry test
    raise ImportError("AWS ACM adapter requires boto3. Install with: pip install netbox-ssl[aws]") from exc

from .base import (
    PROHIBITED_SYNC_FIELDS,
    BaseAdapter,
    CredentialField,
    FetchedCertificate,
)

logger = logging.getLogger("netbox_ssl.adapters.aws_acm")


class AwsAcmAdapter(BaseAdapter):
    """Read-only adapter for AWS Certificate Manager.

    Supports two auth methods:
    - aws_explicit:        operator-supplied access_key_id + secret_access_key (+ optional session_token)
    - aws_instance_role:   boto3 default credential chain (EC2 IMDSv2, ECS task role, Lambda exec role)

    One ExternalSource = one AWS region. Multi-region operators create one
    source per region (matches Lemur/GenericREST one-source-per-endpoint).
    """

    SUPPORTED_AUTH_METHODS: tuple[str, ...] = ("aws_explicit", "aws_instance_role")
    IMPLICIT_AUTH_METHODS: tuple[str, ...] = ("aws_instance_role",)
    REQUIRES_BASE_URL: bool = False
    REQUIRES_REGION: bool = True

    @classmethod
    def credential_schema(cls, auth_method: str) -> dict[str, CredentialField]:
        """Return the credential component schema for a given auth_method.

        - aws_explicit:      access_key_id + secret_access_key + optional session_token
        - aws_instance_role: empty dict (boto3 default credential chain handles it)
        """
        if auth_method == "aws_explicit":
            return {
                "access_key_id": CredentialField(
                    required=True,
                    label="Access Key ID",
                    secret=True,
                    help_text="AWS access key ID for the IAM user/role",
                ),
                "secret_access_key": CredentialField(
                    required=True,
                    label="Secret Access Key",
                    secret=True,
                    help_text="AWS secret access key (env-var ref recommended)",
                ),
                "session_token": CredentialField(
                    required=False,
                    label="Session Token",
                    secret=True,
                    help_text="Optional STS session token for temporary credentials",
                ),
            }
        if auth_method == "aws_instance_role":
            return {}
        raise ValueError(
            f"AwsAcmAdapter does not support auth_method '{auth_method}'. Supported: {list(cls.SUPPORTED_AUTH_METHODS)}"
        )

    # ACM Status string → plugin Certificate.status value.
    # Statuses NOT in this map are skipped during fetch (returns None).
    # FAILED / INACTIVE / VALIDATION_TIMED_OUT have no useful inventory value
    # (no valid PEM, no usable cert) — skip per spec §4.
    _STATUS_MAP: dict[str, str] = {
        "ISSUED": "active",
        "EXPIRED": "expired",
        "REVOKED": "revoked",
        "PENDING_VALIDATION": "pending",
    }

    @staticmethod
    def _map_acm_status(acm_status: str) -> str | None:
        """Map an ACM Status to a plugin Certificate.status, or None to skip.

        Args:
            acm_status: The Status field from ACM DescribeCertificate response.

        Returns:
            Plugin status string (active/expired/revoked/pending) or None.
        """
        return AwsAcmAdapter._STATUS_MAP.get(acm_status)

    def __init__(self, source) -> None:
        super().__init__(source)
        self._client = None  # lazy: built on first use by _get_client()

    def _build_client_kwargs(self) -> dict[str, str]:
        """Build boto3 client kwargs from source credentials + region.

        For aws_explicit: includes aws_access_key_id, aws_secret_access_key,
        and optionally aws_session_token (resolved via Phase 1 multi-cred
        infrastructure).

        For aws_instance_role: omits all credential kwargs so boto3 falls
        back to its default credential chain (EC2 IMDSv2, ECS task role,
        Lambda execution role).

        Returns:
            Mapping suitable for `boto3.client('acm', **kwargs)`.
        """
        kwargs: dict[str, str] = {"region_name": self.source.region}
        if self.source.auth_method == "aws_explicit":
            creds = self.resolve_credentials()  # dict[str, str]
            kwargs["aws_access_key_id"] = creds["access_key_id"]
            kwargs["aws_secret_access_key"] = creds["secret_access_key"]
            if "session_token" in creds:
                kwargs["aws_session_token"] = creds["session_token"]
        # aws_instance_role: no credential kwargs — boto3 default chain handles it
        return kwargs

    def _get_client(self):
        """Lazily build and cache the boto3 ACM client.

        First call constructs the client using kwargs from
        `_build_client_kwargs()`. Subsequent calls return the cached client.

        Returns:
            A boto3 ACM client instance.
        """
        if self._client is None:
            kwargs = self._build_client_kwargs()
            self._client = boto3.client("acm", **kwargs)
        return self._client

    @staticmethod
    def _assert_no_prohibited_keys(response: dict) -> None:
        """Defensive guard — ACM responses must never contain private key material.

        ACM's read-only API (Describe/List/GetCertificate) does not expose
        private keys. This check enforces that invariant: if a hypothetical
        future ACM API change starts returning sensitive fields, the adapter
        fails hard rather than silently leaking them into NetBox.

        Args:
            response: A dict from boto3 (e.g. DescribeCertificate response body).

        Raises:
            ValueError: If any response key matches PROHIBITED_SYNC_FIELDS
                        (case-insensitive comparison).
        """
        keys_lower = {k.lower() for k in response}
        forbidden = keys_lower & PROHIBITED_SYNC_FIELDS
        if forbidden:
            logger.error("ACM response contained prohibited keys: %s", forbidden)
            raise ValueError("Adapter response failed safety check")

    @staticmethod
    def _parse_acm_certificate(describe_response: dict, get_response: dict) -> FetchedCertificate | None:
        """Parse paired DescribeCertificate + GetCertificate responses into FetchedCertificate.

        Returns None if:
        - The cert's Status maps to None (skip — FAILED/INACTIVE/VALIDATION_TIMED_OUT)
        - The PEM in get_response is unparseable
        - Required fields are missing/invalid

        Args:
            describe_response: Body of boto3 ACM describe_certificate() call.
                               Has shape {"Certificate": {...}}.
            get_response:      Body of boto3 ACM get_certificate() call.
                               Has shape {"Certificate": "<PEM>", "CertificateChain": "<PEM>"}.

        Returns:
            FetchedCertificate or None to skip.
        """
        try:
            cert_meta = describe_response["Certificate"]

            # Status filter — skip non-mappable statuses
            status = cert_meta.get("Status", "")
            if AwsAcmAdapter._map_acm_status(status) is None:
                return None

            # KeyAlgorithm parsing: "RSA_2048" → ("rsa", 2048); "EC_prime256v1" → ("ecdsa", None)
            key_alg_raw = cert_meta.get("KeyAlgorithm", "").upper()
            algorithm = "unknown"
            key_size: int | None = None
            if key_alg_raw.startswith("RSA"):
                algorithm = "rsa"
                # "RSA_2048" → 2048
                _, _, size_str = key_alg_raw.partition("_")
                if size_str.isdigit():
                    key_size = int(size_str)
            elif key_alg_raw.startswith("EC"):
                algorithm = "ecdsa"

            # PEM + fingerprint
            pem = get_response.get("Certificate", "")
            if not pem:
                logger.warning(
                    "ACM cert %s has no PEM in GetCertificate response — skipping",
                    cert_meta.get("CertificateArn", "<unknown>"),
                )
                return None

            from cryptography import x509
            from cryptography.hazmat.primitives import hashes

            try:
                x509_cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))
                fingerprint = x509_cert.fingerprint(hashes.SHA256()).hex()
            except (ValueError, TypeError) as e:
                logger.warning(
                    "ACM cert %s has invalid PEM: %s — skipping",
                    cert_meta.get("CertificateArn", "<unknown>"),
                    e,
                )
                return None

            sans_raw = cert_meta.get("SubjectAlternativeNames", [])
            sans = tuple(str(s) for s in sans_raw if s)

            return FetchedCertificate(
                external_id=str(cert_meta["CertificateArn"]),
                common_name=str(cert_meta.get("DomainName", "")),
                serial_number=str(cert_meta.get("Serial", "")),
                fingerprint_sha256=fingerprint,
                issuer=str(cert_meta.get("Issuer", "")),
                valid_from=cert_meta["NotBefore"],
                valid_to=cert_meta["NotAfter"],
                sans=sans,
                key_size=key_size,
                algorithm=algorithm,
                pem_content=pem,
                issuer_chain=str(get_response.get("CertificateChain", "")),
            )
        except (KeyError, TypeError) as e:
            logger.warning("Failed to parse ACM certificate: %s", e)
            return None

    def test_connection(self) -> tuple[bool, str]:
        """Test connectivity to the ACM API. Implemented in Task 14."""
        raise NotImplementedError("Implemented in Task 14")

    def fetch_certificates(self) -> list[FetchedCertificate]:
        """Fetch all certificates. Implemented in Task 12."""
        raise NotImplementedError("Implemented in Task 12")

    def get_certificate_detail(self, external_id: str) -> FetchedCertificate | None:
        """Fetch a single certificate by ARN. Implemented in Task 13."""
        raise NotImplementedError("Implemented in Task 13")
