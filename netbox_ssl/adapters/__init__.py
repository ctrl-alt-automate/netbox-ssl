"""External source adapter framework."""

import logging

from .base import BaseAdapter, CredentialField, FetchedCertificate
from .generic_rest import GenericRESTAdapter
from .lemur import LemurAdapter

logger = logging.getLogger("netbox_ssl.adapters")


def _build_registry() -> dict[str, type[BaseAdapter]]:
    """Build the adapter registry, lazy-importing optional adapters.

    Adapters with optional dependencies (e.g., aws_acm requires the [aws]
    extras for boto3) are wrapped in try/except so a missing extra does
    not break the entire plugin — the adapter is simply unavailable.
    """
    registry: dict[str, type[BaseAdapter]] = {
        "lemur": LemurAdapter,
        "generic_rest": GenericRESTAdapter,
    }
    # Optional adapter — requires netbox-ssl[aws]
    try:
        from .aws_acm import AwsAcmAdapter

        registry["aws_acm"] = AwsAcmAdapter
    except ImportError as exc:
        logger.info(
            "AWS ACM adapter not registered (boto3 not installed): %s. Install with: pip install netbox-ssl[aws]",
            exc,
        )
    return registry


_REGISTRY: dict[str, type[BaseAdapter]] = _build_registry()


def get_adapter_class(source_type: str) -> type[BaseAdapter]:
    """Lookup adapter class for a given source_type.

    Args:
        source_type: The ExternalSource.source_type value.

    Returns:
        The registered adapter class.

    Raises:
        KeyError: If no adapter is registered for the source_type
                  (either unknown source_type, or optional extras missing).
    """
    adapter_cls = _REGISTRY.get(source_type)
    if adapter_cls is None:
        raise KeyError(f"No adapter registered for source type '{source_type}'")
    return adapter_cls


def get_adapter_for_source(source) -> BaseAdapter:
    """Instantiate the correct adapter for a given ExternalSource.

    Args:
        source: An ExternalSource model instance.

    Returns:
        An adapter instance for the source type.

    Raises:
        ValueError: If no adapter is registered for the source type.
    """
    try:
        adapter_cls = get_adapter_class(source.source_type)
    except KeyError as e:
        raise ValueError(str(e)) from e
    return adapter_cls(source)


def get_supported_auth_methods(source_type: str) -> tuple[str, ...]:
    """Return the auth_method values the adapter for source_type accepts.

    Args:
        source_type: The ExternalSource.source_type value.

    Returns:
        Tuple of auth_method identifiers in form-dropdown order.
    """
    return get_adapter_class(source_type).SUPPORTED_AUTH_METHODS


def get_credential_schema(source_type: str, auth_method: str) -> dict[str, CredentialField]:
    """Return the credential schema for a (source_type, auth_method) pair.

    Args:
        source_type: The ExternalSource.source_type value.
        auth_method: The auth_method identifier.

    Returns:
        Mapping of component name -> CredentialField.

    Raises:
        KeyError: If source_type is not registered.
        ValueError: If auth_method is not supported by that adapter.
    """
    return get_adapter_class(source_type).credential_schema(auth_method)


__all__ = [
    "BaseAdapter",
    "CredentialField",
    "FetchedCertificate",
    "get_adapter_class",
    "get_adapter_for_source",
    "get_credential_schema",
    "get_supported_auth_methods",
]
