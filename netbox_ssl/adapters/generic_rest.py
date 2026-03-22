"""Generic REST API adapter for fetching certificates from arbitrary REST APIs."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import requests

from .base import (
    CONNECT_TIMEOUT,
    MAX_SYNC_RESPONSE_BYTES,
    READ_TIMEOUT,
    BaseAdapter,
    FetchedCertificate,
)

logger = logging.getLogger("netbox_ssl.adapters.generic_rest")

# Required field mapping keys
REQUIRED_MAPPING_KEYS: frozenset[str] = frozenset(
    {
        "list_endpoint",
        "external_id",
        "common_name",
        "serial_number",
        "fingerprint_sha256",
        "issuer",
        "valid_from",
        "valid_to",
    }
)

# Optional field mapping keys
OPTIONAL_MAPPING_KEYS: frozenset[str] = frozenset(
    {
        "list_results_path",
        "detail_endpoint",
        "sans",
        "pem_content",
        "key_size",
        "algorithm",
    }
)


def resolve_dotted_path(data: dict | list, path: str) -> object:
    """Resolve a dotted-path notation to a value in a nested dict/list.

    Args:
        data: The root data structure.
        path: A dotted-path string (e.g., "results.items.0.name").

    Returns:
        The resolved value, or None if the path cannot be resolved.
    """
    current: object = data
    for part in path.split("."):
        if current is None:
            return None
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, (list, tuple)):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return current


class GenericRESTAdapter(BaseAdapter):
    """Adapter for generic REST APIs with configurable field mapping.

    The field_mapping JSON on the ExternalSource configures how to map
    API responses to FetchedCertificate fields using dotted-path notation.
    """

    def __init__(self, source) -> None:
        super().__init__(source)
        self._mapping: dict = source.field_mapping or {}

    def _validate_mapping(self) -> list[str]:
        """Validate that required mapping keys are present.

        Returns:
            List of missing required keys.
        """
        return [key for key in REQUIRED_MAPPING_KEYS if key not in self._mapping]

    def _make_request(self, url: str, params: dict | None = None) -> requests.Response:
        """Make an authenticated HTTP request.

        Args:
            url: Full URL to request.
            params: Optional query parameters.

        Returns:
            The HTTP response.

        Raises:
            requests.RequestException: On network or HTTP errors.
            ValueError: If response exceeds size limit.
        """
        headers = self._get_headers()
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            allow_redirects=False,
            verify=self.source.verify_ssl,
        )
        content_length = len(response.content)
        if content_length > MAX_SYNC_RESPONSE_BYTES:
            raise ValueError(
                f"Response size ({content_length} bytes) exceeds maximum ({MAX_SYNC_RESPONSE_BYTES} bytes)"
            )
        response.raise_for_status()
        return response

    def _build_url(self, endpoint: str) -> str:
        """Build a full URL from a relative endpoint path.

        Args:
            endpoint: The API endpoint path (e.g., "/api/certificates").

        Returns:
            The full URL.
        """
        base = self.source.base_url.rstrip("/")
        endpoint = endpoint.lstrip("/")
        return f"{base}/{endpoint}"

    def test_connection(self) -> tuple[bool, str]:
        """Test connectivity to the generic REST API.

        Returns:
            Tuple of (success, message).
        """
        missing = self._validate_mapping()
        if missing:
            return False, f"Missing required field mappings: {', '.join(sorted(missing))}"

        try:
            list_endpoint = self._mapping["list_endpoint"]
            url = self._build_url(list_endpoint)
            self._make_request(url)
            return True, "Connection successful"
        except requests.RequestException as e:
            logger.warning("Generic REST connection test failed for '%s': %s", self.source.name, e)
            return False, f"Connection failed: {type(e).__name__}"
        except Exception as e:
            logger.error(
                "Unexpected error testing Generic REST connection for '%s': %s",
                self.source.name,
                e,
            )
            return False, "Connection test failed due to an unexpected error"

    def fetch_certificates(self) -> list[FetchedCertificate]:
        """Fetch all certificates from the generic REST API.

        Returns:
            List of FetchedCertificate objects.
        """
        missing = self._validate_mapping()
        if missing:
            logger.error(
                "Cannot fetch certificates from '%s': missing mappings %s",
                self.source.name,
                missing,
            )
            return []

        list_endpoint = self._mapping["list_endpoint"]
        url = self._build_url(list_endpoint)

        try:
            response = self._make_request(url)
            data = response.json()
        except requests.RequestException as e:
            logger.error("Failed to fetch certificates from '%s': %s", self.source.name, e)
            return []
        except ValueError as e:
            logger.error("Invalid response from '%s': %s", self.source.name, e)
            return []

        # Resolve the results list from the response
        results_path = self._mapping.get("list_results_path")
        if results_path:
            items = resolve_dotted_path(data, results_path)
            if not isinstance(items, list):
                logger.error(
                    "Expected list at path '%s' in response from '%s', got %s",
                    results_path,
                    self.source.name,
                    type(items).__name__,
                )
                return []
        elif isinstance(data, list):
            items = data
        else:
            logger.error(
                "Response from '%s' is not a list and no list_results_path configured",
                self.source.name,
            )
            return []

        certificates: list[FetchedCertificate] = []
        for item in items:
            cert = self._parse_item(item)
            if cert is not None:
                certificates.append(cert)

        logger.info(
            "Fetched %d certificates from Generic REST '%s'",
            len(certificates),
            self.source.name,
        )
        return certificates

    def get_certificate_detail(self, external_id: str) -> FetchedCertificate | None:
        """Fetch a single certificate by its external ID.

        Args:
            external_id: The identifier in the external system.

        Returns:
            FetchedCertificate or None if not found.
        """
        detail_endpoint = self._mapping.get("detail_endpoint")
        if not detail_endpoint:
            logger.warning(
                "No detail_endpoint configured for '%s', cannot fetch detail",
                self.source.name,
            )
            return None

        # Substitute {id} in the detail endpoint
        endpoint = detail_endpoint.replace("{id}", str(external_id))
        url = self._build_url(endpoint)

        try:
            response = self._make_request(url)
            data = response.json()
            return self._parse_item(data)
        except requests.RequestException as e:
            logger.warning(
                "Failed to fetch certificate %s from '%s': %s",
                external_id,
                self.source.name,
                e,
            )
            return None

    def _parse_item(self, item: dict) -> FetchedCertificate | None:
        """Parse a single API response item into a FetchedCertificate.

        Args:
            item: Dictionary from the API response.

        Returns:
            FetchedCertificate or None if required fields are missing.
        """
        try:
            external_id = str(resolve_dotted_path(item, self._mapping["external_id"]) or "")
            if not external_id:
                return None

            common_name = str(resolve_dotted_path(item, self._mapping["common_name"]) or "")
            serial_number = str(resolve_dotted_path(item, self._mapping["serial_number"]) or "")
            fingerprint = str(resolve_dotted_path(item, self._mapping["fingerprint_sha256"]) or "")
            issuer = str(resolve_dotted_path(item, self._mapping["issuer"]) or "")

            valid_from_raw = resolve_dotted_path(item, self._mapping["valid_from"])
            valid_to_raw = resolve_dotted_path(item, self._mapping["valid_to"])

            valid_from = _parse_datetime(str(valid_from_raw)) if valid_from_raw else None
            valid_to = _parse_datetime(str(valid_to_raw)) if valid_to_raw else None

            if not all([common_name, serial_number, fingerprint, issuer, valid_from, valid_to]):
                return None

            # Optional fields
            sans_raw = resolve_dotted_path(item, self._mapping["sans"]) if "sans" in self._mapping else None
            sans = list(sans_raw) if isinstance(sans_raw, (list, tuple)) else []

            pem_content = ""
            if "pem_content" in self._mapping:
                pem_raw = resolve_dotted_path(item, self._mapping["pem_content"])
                pem_content = str(pem_raw) if pem_raw else ""

            key_size = None
            if "key_size" in self._mapping:
                ks_raw = resolve_dotted_path(item, self._mapping["key_size"])
                if ks_raw is not None:
                    import contextlib

                    with contextlib.suppress(ValueError, TypeError):
                        key_size = int(ks_raw)

            algorithm = "unknown"
            if "algorithm" in self._mapping:
                algo_raw = resolve_dotted_path(item, self._mapping["algorithm"])
                if algo_raw:
                    algorithm = str(algo_raw).lower()

            return FetchedCertificate(
                external_id=external_id,
                common_name=common_name,
                serial_number=serial_number,
                fingerprint_sha256=fingerprint,
                issuer=issuer,
                valid_from=valid_from,
                valid_to=valid_to,
                sans=sans,
                key_size=key_size,
                algorithm=algorithm,
                pem_content=pem_content,
            )
        except (KeyError, TypeError, ValueError) as e:
            logger.warning("Failed to parse item from '%s': %s", self.source.name, e)
            return None


def _parse_datetime(value: str) -> datetime | None:
    """Parse a datetime string.

    Args:
        value: ISO 8601 datetime string.

    Returns:
        datetime object or None if parsing fails.
    """
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, AttributeError):
        pass
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            dt = datetime.strptime(value, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None
