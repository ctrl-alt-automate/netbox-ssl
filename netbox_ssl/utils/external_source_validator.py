"""Schema-compliance validation for ExternalSource credentials.

Shared by forms, serializers, and any other caller that needs to validate
an auth_credentials dict against an adapter's declared schema. Keeps
validation logic in one place so form and API cannot drift.
"""

from __future__ import annotations

from django.core.exceptions import ValidationError

from ..adapters import get_adapter_class
from .credential_resolver import ENV_VAR_PATTERN, CredentialResolver


class ExternalSourceSchemaValidator:
    """Validate an ExternalSource payload against adapter requirements.

    All validation methods raise Django ValidationError with a dict of
    field-specific errors so callers (form, serializer) can surface them
    at the right field in their UI.
    """

    @staticmethod
    def validate(
        source_type: str,
        auth_method: str,
        auth_credentials: dict,
        base_url: str | None = None,
        region: str | None = None,
    ) -> None:
        """Validate credential payload + adapter requirements.

        Args:
            source_type:      The ExternalSource.source_type value.
            auth_method:      The auth_method identifier.
            auth_credentials: The credential references dict to validate.
            base_url:         The ExternalSource.base_url value.
                              Pass an empty string ``""`` to trigger the
                              "required but missing" validation check.
                              Omit (or pass ``None``) to skip the check.
            region:           The ExternalSource.region value.
                              Same sentinel convention as base_url.

        Raises:
            ValidationError: With a field-specific error dict.
        """
        # 1. source_type must be known
        try:
            adapter_cls = get_adapter_class(source_type)
        except KeyError:
            raise ValidationError({"source_type": f"Unknown source_type '{source_type}'"}) from None

        # 2. auth_method must be supported by this adapter
        if auth_method not in adapter_cls.SUPPORTED_AUTH_METHODS:
            raise ValidationError(
                {
                    "auth_method": (
                        f"{adapter_cls.__name__} does not support auth_method "
                        f"'{auth_method}'. "
                        f"Supported: {list(adapter_cls.SUPPORTED_AUTH_METHODS)}"
                    )
                }
            )

        # 3. Adapter endpoint requirements (base_url, region)
        # Only checked when the caller explicitly supplies the value (not None).
        # An empty string triggers the "required but missing" error; None skips.
        if base_url is not None and adapter_cls.REQUIRES_BASE_URL and not base_url:
            raise ValidationError({"base_url": f"{adapter_cls.__name__} requires a base URL."})
        if region is not None and adapter_cls.REQUIRES_REGION and not region:
            raise ValidationError({"region": (f"{adapter_cls.__name__} requires a region (e.g., 'us-east-1').")})

        # 4. Schema compliance for auth_credentials
        schema = adapter_cls.credential_schema(auth_method)

        extra_keys = set(auth_credentials.keys()) - set(schema.keys())
        if extra_keys:
            raise ValidationError(
                {
                    "auth_credentials": (
                        f"Unknown credential keys: {sorted(extra_keys)}. Allowed: {sorted(schema.keys())}"
                    )
                }
            )

        for key, field_spec in schema.items():
            if field_spec.required and key not in auth_credentials:
                raise ValidationError(
                    {"auth_credentials": (f"Missing required credential '{key}' ({field_spec.label or key})")}
                )

        # 5. Reference format — strict match against ENV_VAR_PATTERN
        for key, ref in auth_credentials.items():
            if not isinstance(ref, str) or not ref.strip():
                raise ValidationError(
                    {"auth_credentials": (f"Credential '{key}' must be a non-empty string reference")}
                )

            if ":" in ref:
                scheme, _, path = ref.partition(":")
                scheme = scheme.strip().lower()
                path = path.strip()
                if scheme not in CredentialResolver.SUPPORTED_SCHEMES:
                    raise ValidationError(
                        {
                            "auth_credentials": (
                                f"Credential '{key}' uses unsupported scheme "
                                f"'{scheme}'. "
                                f"Supported: {sorted(CredentialResolver.SUPPORTED_SCHEMES)}"
                            )
                        }
                    )
                if not path:
                    raise ValidationError(
                        {
                            "auth_credentials": (
                                f"Credential '{key}' has an empty path after "
                                f"'{scheme}:'. Provide an env-var name, e.g. 'env:MY_TOKEN'."
                            )
                        }
                    )
                var_name = path
            else:
                var_name = ref.strip()

            # 6. Env-var name must match the resolver's allowed pattern
            if not ENV_VAR_PATTERN.match(var_name):
                raise ValidationError(
                    {
                        "auth_credentials": (
                            f"Credential '{key}' references '{var_name}', which is "
                            "not a valid environment variable name. "
                            "Names must start with an uppercase letter or underscore "
                            "and contain only uppercase letters, digits, and underscores."
                        )
                    }
                )
