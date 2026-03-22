"""Credential resolution for external sources."""

import logging
import os
import re

logger = logging.getLogger("netbox_ssl.credentials")

_ENV_VAR_PATTERN = re.compile(r"^[A-Z_][A-Z0-9_]{0,254}$")


class CredentialResolveError(Exception):
    """Raised when a credential reference cannot be resolved."""


class CredentialResolver:
    """Resolve credential references to actual values.

    Supported schemes:
    - env:VAR_NAME — read from environment variable
    - bare string — treated as env var name (backward compat)
    """

    SUPPORTED_SCHEMES: frozenset[str] = frozenset({"env"})

    @classmethod
    def resolve(cls, reference: str) -> str:
        """Resolve a credential reference to its actual value.

        Args:
            reference: A credential reference string (e.g., "env:MY_TOKEN" or "MY_TOKEN").

        Returns:
            The resolved credential value.

        Raises:
            CredentialResolveError: If the reference cannot be resolved.
        """
        if not reference:
            raise CredentialResolveError("Empty credential reference")

        if ":" not in reference:
            logger.info(
                "Resolving bare credential reference '%s' as env var. Consider using the 'env:%s' prefix for clarity.",
                reference,
                reference,
            )
            return cls._resolve_env(reference)

        scheme, _, path = reference.partition(":")
        scheme = scheme.lower().strip()
        path = path.strip()

        if scheme == "env":
            return cls._resolve_env(path)
        raise CredentialResolveError(
            f"Unsupported credential scheme '{scheme}'. Supported: {sorted(cls.SUPPORTED_SCHEMES)}"
        )

    @classmethod
    def _resolve_env(cls, var_name: str) -> str:
        """Resolve an environment variable credential.

        Args:
            var_name: The environment variable name.

        Returns:
            The environment variable value.

        Raises:
            CredentialResolveError: If the variable name is invalid or not set.
        """
        if not _ENV_VAR_PATTERN.match(var_name):
            raise CredentialResolveError("Invalid environment variable name format")
        value = os.environ.get(var_name)
        if value is None:
            raise CredentialResolveError(f"Environment variable '{var_name}' is not set")
        return value
