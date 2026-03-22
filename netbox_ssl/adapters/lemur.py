"""Lemur adapter for fetching certificates from Netflix Lemur."""

from __future__ import annotations

import logging
from urllib.parse import urlparse

import requests

from .base import (
    BaseAdapter,
    FetchedCertificate,
)

logger = logging.getLogger("netbox_ssl.adapters.lemur")

# Safety limit: stop following pagination after this many pages
MAX_PAGES: int = 1000


class LemurAdapter(BaseAdapter):
    """Adapter for Netflix Lemur certificate management system.

    Lemur API docs: https://lemur.readthedocs.io/
    Uses GET {base_url}/api/1/certificates with Bearer auth.
    """

    def _validate_pagination_url(self, next_url: str) -> bool:
        """Validate that a pagination URL shares the same origin as the base URL.

        Prevents SSRF by ensuring ``next`` links do not redirect to
        arbitrary hosts.

        Args:
            next_url: The URL from a pagination ``next`` field.

        Returns:
            True if the URL is safe to follow.
        """
        try:
            base_parsed = urlparse(self.source.base_url)
            next_parsed = urlparse(next_url)
            if next_parsed.scheme != "https":
                logger.warning(
                    "Pagination URL rejected: scheme '%s' is not https",
                    next_parsed.scheme,
                )
                return False
            if next_parsed.netloc != base_parsed.netloc:
                logger.warning(
                    "Pagination URL rejected: netloc '%s' != '%s'",
                    next_parsed.netloc,
                    base_parsed.netloc,
                )
                return False
            return True
        except Exception:
            return False

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
        pages_fetched = 0

        while url:
            if pages_fetched >= MAX_PAGES:
                logger.warning(
                    "Reached maximum pagination limit (%d pages) for Lemur '%s'",
                    MAX_PAGES,
                    self.source.name,
                )
                break

            try:
                response = self._make_request(url)
                data = response.json()
            except requests.RequestException as e:
                logger.error("Failed to fetch certificates from Lemur '%s': %s", self.source.name, e)
                break
            except ValueError as e:
                logger.error("Invalid response from Lemur '%s': %s", self.source.name, e)
                break

            pages_fetched += 1

            items = data.get("items", [])
            for item in items:
                cert = self._parse_lemur_certificate(item)
                if cert is not None:
                    certificates.append(cert)

            # Handle pagination — validate next URL against SSRF
            next_url = data.get("next")
            url = next_url if next_url and self._validate_pagination_url(next_url) else None

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

            valid_from = BaseAdapter._parse_datetime(valid_from_str) if valid_from_str else None
            valid_to = BaseAdapter._parse_datetime(valid_to_str) if valid_to_str else None

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

            # MED-9: Prefer SHA256 fingerprint; Lemur's "fingerprint" field is
            # often SHA1.  Use SHA256 if available, else fall back to the
            # generic fingerprint field as a last resort.
            fingerprint = data.get("sha256", "") or data.get("fingerprint", "")

            return FetchedCertificate(
                external_id=external_id,
                common_name=data.get("cn", "") or data.get("commonName", "") or data.get("common_name", ""),
                serial_number=data.get("serialNumber", "") or data.get("serial_number", ""),
                fingerprint_sha256=fingerprint,
                issuer=data.get("issuer", ""),
                valid_from=valid_from,
                valid_to=valid_to,
                sans=tuple(sans),
                key_size=data.get("bits") or data.get("keySize") or data.get("key_size"),
                algorithm=algorithm,
                pem_content=data.get("body", "") or data.get("pem", ""),
                issuer_chain=data.get("chain", ""),
            )
        except (KeyError, TypeError, ValueError) as e:
            logger.warning("Failed to parse Lemur certificate: %s", e)
            return None
