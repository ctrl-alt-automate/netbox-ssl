"""External source adapter framework."""

from .base import BaseAdapter, FetchedCertificate
from .generic_rest import GenericRESTAdapter
from .lemur import LemurAdapter

_REGISTRY: dict[str, type[BaseAdapter]] = {
    "lemur": LemurAdapter,
    "generic_rest": GenericRESTAdapter,
}


def get_adapter_for_source(source) -> BaseAdapter:
    """Instantiate the correct adapter for a given ExternalSource.

    Args:
        source: An ExternalSource model instance.

    Returns:
        An adapter instance for the source type.

    Raises:
        ValueError: If no adapter is registered for the source type.
    """
    adapter_cls = _REGISTRY.get(source.source_type)
    if adapter_cls is None:
        raise ValueError(f"No adapter registered for source type '{source.source_type}'")
    return adapter_cls(source)


__all__ = ["BaseAdapter", "FetchedCertificate", "get_adapter_for_source"]
