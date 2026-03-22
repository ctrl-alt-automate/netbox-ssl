"""Lemur adapter for fetching certificates from Netflix Lemur."""

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

logger = logging.getLogger("netbox_ssl.adapters.lemur")


class LemurAdapter(BaseAdapter):
    """Adapter for Netflix Lemur certificate management system.

    Lemur API docs: https://lemur.readthedocs.io/
    Uses GET {base_url}/api/1/certificates with Bearer auth.
    """

    def _make_request(self, url: str, params: dict | None = None) -> requests.Response:
        """Make an authenticated HTTP request to the Lemur API.

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
        # Check response size
        content_length = len(response.content)
        if content_length > MAX_SYNC_RESPONSE_BYTES:
            raise ValueError(
                f"Response size ({content_length} bytes) exceeds maximum ({MAX_SYNC_RESPONSE_BYTES} bytes)"
            )
        response.raise_for_status()
        return response

    def test_connection(self) -> tuple[bool, str]:
        """Test connectivity to the Lemur API.

        Returns:
            Tuple of (success, message).
        """
        try:
            url = f"{self.source.base_url.rstrip('/')}/api/1/certificates"
            self._make_request(url, params={"count": 1})
            return True, "Connection successful"
        except requests.RequestException as e:
            logger.warning("Lemur connection test failed for '%s': %s", self.source.name, e)
            return False, f"Connection failed: {type(e).__name__}"
        except Exception as e:
            logger.error("Unexpected error testing Lemur connection for '%s': %s", self.source.name, e)
            return False, "Connection test failed due to an unexpected error"

    def fetch_certificates(self) -> list[FetchedCertificate]:
        """Fetch all certificates from Lemur with pagination.

        Returns:
            List of FetchedCertificate objects.
        """
        certificates: list[FetchedCertificate] = []
        url: str | None = f"{self.source.base_url.rstrip('/')}/api/1/certificates"

        while url:
            try:
                response = self._make_request(url)
                data = response.json()
            except requests.RequestException as e:
                logger.error("Failed to fetch certificates from Lemur '%s': %s", self.source.name, e)
                break
            except ValueError as e:
                logger.error("Invalid response from Lemur '%s': %s", self.source.name, e)
                break

            items = data.get("items", [])
            for item in items:
                cert = self._parse_lemur_certificate(item)
                if cert is not None:
                    certificates.append(cert)

            # Handle pagination
            url = data.get("next")

        logger.info("Fetched %d certificates from Lemur '%s'", len(certificates), self.source.name)
        return certificates

    def get_certificate_detail(self, external_id: str) -> FetchedCertificate | None:
        """Fetch a single certificate from Lemur by ID.

        Args:
            external_id: The Lemur certificate ID.

        Returns:
            FetchedCertificate or None if not found.
        """
        url = f"{self.source.base_url.rstrip('/')}/api/1/certificates/{external_id}"
        try:
            response = self._make_request(url)
            data = response.json()
            return self._parse_lemur_certificate(data)
        except requests.RequestException as e:
            logger.warning(
                "Failed to fetch certificate %s from Lemur '%s': %s",
                external_id,
                self.source.name,
                e,
            )
            return None

    @staticmethod
    def _parse_lemur_certificate(data: dict) -> FetchedCertificate | None:
        """Parse a Lemur API certificate response into a FetchedCertificate.

        Args:
            data: Dictionary from Lemur API response.

        Returns:
            FetchedCertificate or None if required fields are missing.
        """
        try:
            external_id = str(data.get("id", ""))
            if not external_id:
                return None

            # Parse dates — Lemur uses ISO 8601 format
            valid_from_str = data.get("notBefore", "") or data.get("not_before", "")
            valid_to_str = data.get("notAfter", "") or data.get("not_after", "")

            valid_from = _parse_datetime(valid_from_str) if valid_from_str else None
            valid_to = _parse_datetime(valid_to_str) if valid_to_str else None

            if not valid_from or not valid_to:
                return None

            # Extract SANs from Lemur's extensions
            sans: list[str] = []
            extensions = data.get("extensions", {})
            if isinstance(extensions, dict):
                san_data = extensions.get("subAltNames", {}) or extensions.get("sub_alt_names", {})
                if isinstance(san_data, dict):
                    names = san_data.get("names", [])
                    for name in names:
                        if isinstance(name, dict):
                            value = name.get("value", "")
                            if value:
                                sans.append(value)
                        elif isinstance(name, str):
                            sans.append(name)
                elif isinstance(san_data, list):
                    sans = [str(s) for s in san_data if s]

            # Map key type
            key_type = (data.get("keyType", "") or data.get("key_type", "")).upper()
            algorithm = "unknown"
            if "RSA" in key_type:
                algorithm = "rsa"
            elif "EC" in key_type or "ECDSA" in key_type:
                algorithm = "ecdsa"

            return FetchedCertificate(
                external_id=external_id,
                common_name=data.get("cn", "") or data.get("commonName", "") or data.get("common_name", ""),
                serial_number=data.get("serialNumber", "") or data.get("serial_number", ""),
                fingerprint_sha256=data.get("fingerprint", "") or data.get("sha256", ""),
                issuer=data.get("issuer", ""),
                valid_from=valid_from,
                valid_to=valid_to,
                sans=sans,
                key_size=data.get("bits") or data.get("keySize") or data.get("key_size"),
                algorithm=algorithm,
                pem_content=data.get("body", "") or data.get("pem", ""),
                issuer_chain=data.get("chain", ""),
            )
        except (KeyError, TypeError, ValueError) as e:
            logger.warning("Failed to parse Lemur certificate: %s", e)
            return None


def _parse_datetime(value: str) -> datetime | None:
    """Parse a datetime string from Lemur API.

    Args:
        value: ISO 8601 datetime string.

    Returns:
        datetime object or None if parsing fails.
    """
    if not value:
        return None
    try:
        # Try ISO format first (Python 3.11+)
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, AttributeError):
        pass
    # Try common Lemur date formats
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            dt = datetime.strptime(value, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None
