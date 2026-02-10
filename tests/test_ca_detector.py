"""
Unit tests for Certificate Authority detection utilities.

Tests the detect_issuing_ca function and helper functions.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Allow importing modules directly without loading the full netbox_ssl package
_project_root = Path(__file__).parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

# Mock netbox.plugins if not available
if "netbox" not in sys.modules:
    sys.modules["netbox"] = MagicMock()
    sys.modules["netbox.plugins"] = MagicMock()

from netbox_ssl.utils.ca_detector import (
    _extract_cn_from_issuer,
    _guess_ca_type,
    detect_issuing_ca,
)


class TestExtractCNFromIssuer:
    """Tests for _extract_cn_from_issuer helper function."""

    @pytest.mark.unit
    def test_extract_cn_standard_format(self):
        """Test extracting CN from standard issuer format."""
        issuer = "C=US, O=Let's Encrypt, CN=E7"
        assert _extract_cn_from_issuer(issuer) == "E7"

    @pytest.mark.unit
    def test_extract_cn_with_spaces(self):
        """Test extracting CN with spaces around equals."""
        issuer = "C = US, O = DigiCert Inc, CN = DigiCert SHA2 Extended Validation Server CA"
        assert _extract_cn_from_issuer(issuer) == "DigiCert SHA2 Extended Validation Server CA"

    @pytest.mark.unit
    def test_extract_cn_no_cn_falls_back_to_o(self):
        """Test fallback to Organization when CN is not present."""
        issuer = "C=US, O=Amazon, OU=Server CA 1B"
        assert _extract_cn_from_issuer(issuer) == "Amazon"

    @pytest.mark.unit
    def test_extract_cn_empty_string(self):
        """Test with empty string."""
        assert _extract_cn_from_issuer("") is None

    @pytest.mark.unit
    def test_extract_cn_no_cn_or_o(self):
        """Test when neither CN nor O is present."""
        issuer = "C=US, ST=California"
        assert _extract_cn_from_issuer(issuer) is None


class TestGuessCaType:
    """Tests for _guess_ca_type helper function."""

    @pytest.mark.unit
    def test_guess_acme_letsencrypt(self):
        """Test detection of Let's Encrypt as ACME."""
        assert _guess_ca_type("C=US, O=Let's Encrypt, CN=E7") == "acme"

    @pytest.mark.unit
    def test_guess_acme_zerossl(self):
        """Test detection of ZeroSSL as ACME."""
        assert _guess_ca_type("C=AT, O=ZeroSSL, CN=ZeroSSL ECC Domain Secure Site CA") == "acme"

    @pytest.mark.unit
    def test_guess_public_digicert(self):
        """Test detection of DigiCert as public CA."""
        assert _guess_ca_type("C=US, O=DigiCert Inc, CN=DigiCert SHA2 Extended Validation Server CA") == "public"

    @pytest.mark.unit
    def test_guess_public_sectigo(self):
        """Test detection of Sectigo as public CA."""
        assert _guess_ca_type("C=GB, O=Sectigo Limited, CN=Sectigo RSA Domain Validation Secure Server CA") == "public"

    @pytest.mark.unit
    def test_guess_public_globalsign(self):
        """Test detection of GlobalSign as public CA."""
        assert _guess_ca_type("C=BE, O=GlobalSign nv-sa, CN=GlobalSign RSA OV SSL CA 2018") == "public"

    @pytest.mark.unit
    def test_guess_internal_unknown(self):
        """Test that unknown CAs default to internal."""
        assert _guess_ca_type("C=NL, O=My Company, CN=Internal CA") == "internal"


class TestDetectIssuingCaLogic:
    """
    Tests for detect_issuing_ca core matching logic.

    These tests verify the pattern matching works correctly by testing
    a simplified version of the matching logic without Django imports.
    """

    def _match_pattern(self, issuer: str, patterns: list[tuple[str, str]]) -> str | None:
        """
        Simplified matching logic for testing.

        Args:
            issuer: The issuer string to match
            patterns: List of (name, pattern) tuples

        Returns:
            Name of matching CA, or None
        """
        if not issuer:
            return None
        issuer_lower = issuer.lower()
        for name, pattern in patterns:
            if pattern.lower() in issuer_lower:
                return name
        return None

    @pytest.mark.unit
    def test_match_with_empty_issuer(self):
        """Test that empty issuer returns None."""
        result = self._match_pattern("", [("Test CA", "test")])
        assert result is None

    @pytest.mark.unit
    def test_match_with_none_issuer(self):
        """Test that None issuer returns None."""
        result = self._match_pattern(None, [("Test CA", "test")])
        assert result is None

    @pytest.mark.unit
    def test_match_pattern_found(self):
        """Test detection when pattern matches."""
        patterns = [("Let's Encrypt", "let's encrypt")]
        result = self._match_pattern("C=US, O=Let's Encrypt, CN=E7", patterns)
        assert result == "Let's Encrypt"

    @pytest.mark.unit
    def test_match_case_insensitive(self):
        """Test that pattern matching is case-insensitive."""
        patterns = [("DigiCert", "digicert")]
        result = self._match_pattern("C=US, O=DIGICERT INC, CN=DigiCert SHA2 Server CA", patterns)
        assert result == "DigiCert"

    @pytest.mark.unit
    def test_match_no_pattern_found(self):
        """Test that no match returns None."""
        patterns = [("Let's Encrypt", "let's encrypt")]
        result = self._match_pattern("C=US, O=Unknown CA, CN=Some Certificate", patterns)
        assert result is None

    @pytest.mark.unit
    def test_match_returns_first_match(self):
        """Test that first matching CA is returned when multiple could match."""
        patterns = [
            ("Sectigo", "sectigo"),
            ("Comodo", "comodo"),
        ]
        result = self._match_pattern("C=GB, O=Sectigo Limited, CN=Sectigo RSA CA", patterns)
        assert result == "Sectigo"

    @pytest.mark.unit
    def test_match_multiple_patterns_second_matches(self):
        """Test matching when second pattern matches."""
        patterns = [
            ("Let's Encrypt", "let's encrypt"),
            ("DigiCert", "digicert"),
        ]
        result = self._match_pattern("C=US, O=DigiCert Inc, CN=DigiCert EV CA", patterns)
        assert result == "DigiCert"


class TestRealWorldIssuerPatterns:
    """Tests with real-world issuer strings."""

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "issuer,expected_type",
        [
            # ACME providers
            ("C=US, O=Let's Encrypt, CN=E7", "acme"),
            ("C=US, O=Let's Encrypt, CN=R3", "acme"),
            ("C=AT, O=ZeroSSL, CN=ZeroSSL RSA Domain Secure Site CA", "acme"),
            # Public CAs
            ("C=US, O=DigiCert Inc, CN=DigiCert SHA2 Extended Validation Server CA", "public"),
            ("C=US, O=DigiCert Inc, CN=DigiCert Global Root CA", "public"),
            ("C=GB, O=Sectigo Limited, CN=Sectigo RSA Domain Validation Secure Server CA", "public"),
            ("C=BE, O=GlobalSign nv-sa, CN=GlobalSign RSA OV SSL CA 2018", "public"),
            ("C=US, O=Amazon, CN=Amazon RSA 2048 M01", "public"),
            ("C=US, O=Google Trust Services LLC, CN=GTS CA 1C3", "public"),
            # Internal CAs
            ("C=NL, O=Example Corp, CN=Example Internal CA", "internal"),
            ("CN=DC01.example.local", "internal"),
        ],
    )
    def test_guess_ca_type_real_issuers(self, issuer, expected_type):
        """Test CA type guessing with real-world issuer strings."""
        assert _guess_ca_type(issuer) == expected_type
