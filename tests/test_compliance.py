"""
Unit tests for compliance reporting functionality.

Tests the compliance policy enforcement and check result tracking
for certificates against defined compliance rules.
"""

from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest

from netbox_ssl.utils.compliance_checker import CheckResult, ComplianceChecker

# Mark all tests in this module as unit tests
pytestmark = pytest.mark.unit


def _create_mock_certificate(**kwargs):
    """Create a mock certificate with specified attributes."""
    cert = MagicMock()
    cert.key_size = kwargs.get("key_size", 4096)
    cert.algorithm = kwargs.get("algorithm", "rsa")
    cert.common_name = kwargs.get("common_name", "example.com")
    cert.issuer = kwargs.get("issuer", "CN=DigiCert")
    cert.issuer_chain = kwargs.get("issuer_chain", "")
    cert.sans = kwargs.get("sans", [])
    cert.days_remaining = kwargs.get("days_remaining", 60)
    cert.valid_from = kwargs.get("valid_from", datetime(2024, 1, 1))
    cert.valid_to = kwargs.get("valid_to", datetime(2024, 12, 31))
    cert.tenant = kwargs.get("tenant")
    return cert


class TestComplianceCheckerMinKeySize:
    """Test cases for minimum key size compliance checks."""

    def test_key_size_passes_when_meets_minimum(self):
        """Test that key size check passes when meeting minimum."""
        cert = _create_mock_certificate(key_size=4096)
        result = ComplianceChecker._check_min_key_size(cert, {"min_bits": 2048})

        assert result.passed is True
        assert "4096" in result.message

    def test_key_size_fails_when_below_minimum(self):
        """Test that key size check fails when below minimum."""
        cert = _create_mock_certificate(key_size=1024)
        result = ComplianceChecker._check_min_key_size(cert, {"min_bits": 2048})

        assert result.passed is False
        assert "below" in result.message.lower()

    def test_key_size_passes_at_exact_minimum(self):
        """Test that key size check passes at exact minimum."""
        cert = _create_mock_certificate(key_size=2048)
        result = ComplianceChecker._check_min_key_size(cert, {"min_bits": 2048})

        assert result.passed is True

    def test_key_size_fails_when_none(self):
        """Test that key size check fails when key_size is None."""
        cert = _create_mock_certificate(key_size=None)
        result = ComplianceChecker._check_min_key_size(cert, {"min_bits": 2048})

        assert result.passed is False
        assert "not set" in result.message.lower()

    def test_key_size_uses_default_minimum(self):
        """Test that default minimum of 2048 is used when not specified."""
        cert = _create_mock_certificate(key_size=2048)
        result = ComplianceChecker._check_min_key_size(cert, {})

        assert result.passed is True


class TestComplianceCheckerMaxValidityDays:
    """Test cases for maximum validity period compliance checks."""

    def test_validity_passes_when_within_limit(self):
        """Test that validity check passes when within limit."""
        cert = _create_mock_certificate(
            valid_from=datetime(2024, 1, 1),
            valid_to=datetime(2024, 12, 31),
        )
        result = ComplianceChecker._check_max_validity_days(cert, {"max_days": 397})

        assert result.passed is True

    def test_validity_fails_when_exceeds_limit(self):
        """Test that validity check fails when exceeding limit."""
        cert = _create_mock_certificate(
            valid_from=datetime(2024, 1, 1),
            valid_to=datetime(2026, 1, 1),  # 2 years
        )
        result = ComplianceChecker._check_max_validity_days(cert, {"max_days": 397})

        assert result.passed is False
        assert "exceeds" in result.message.lower()

    def test_validity_passes_at_exact_limit(self):
        """Test that validity check passes at exact limit."""
        cert = _create_mock_certificate(
            valid_from=datetime(2024, 1, 1),
            valid_to=datetime(2024, 1, 1) + timedelta(days=397),
        )
        result = ComplianceChecker._check_max_validity_days(cert, {"max_days": 397})

        assert result.passed is True

    def test_validity_fails_when_dates_not_set(self):
        """Test that validity check fails when dates are not set."""
        cert = _create_mock_certificate(valid_from=None, valid_to=None)
        result = ComplianceChecker._check_max_validity_days(cert, {"max_days": 397})

        assert result.passed is False
        assert "not set" in result.message.lower()


class TestComplianceCheckerAlgorithm:
    """Test cases for algorithm compliance checks."""

    def test_algorithm_allowed_passes_with_valid_algorithm(self):
        """Test that allowed algorithm check passes for valid algorithms."""
        cert = _create_mock_certificate(algorithm="rsa")
        result = ComplianceChecker._check_algorithm_allowed(cert, {"algorithms": ["rsa", "ecdsa", "ed25519"]})

        assert result.passed is True
        assert "allowed list" in result.message.lower()

    def test_algorithm_allowed_fails_with_invalid_algorithm(self):
        """Test that allowed algorithm check fails for invalid algorithms."""
        cert = _create_mock_certificate(algorithm="dsa")
        result = ComplianceChecker._check_algorithm_allowed(cert, {"algorithms": ["rsa", "ecdsa", "ed25519"]})

        assert result.passed is False
        assert "not in allowed" in result.message.lower()

    def test_algorithm_allowed_is_case_insensitive(self):
        """Test that algorithm check is case-insensitive."""
        cert = _create_mock_certificate(algorithm="RSA")
        result = ComplianceChecker._check_algorithm_allowed(cert, {"algorithms": ["rsa"]})

        assert result.passed is True

    def test_algorithm_forbidden_passes_when_not_forbidden(self):
        """Test that forbidden algorithm check passes when not using forbidden."""
        cert = _create_mock_certificate(algorithm="ecdsa")
        result = ComplianceChecker._check_algorithm_forbidden(cert, {"algorithms": ["dsa", "md5"]})

        assert result.passed is True

    def test_algorithm_forbidden_fails_when_using_forbidden(self):
        """Test that forbidden algorithm check fails when using forbidden."""
        cert = _create_mock_certificate(algorithm="dsa")
        result = ComplianceChecker._check_algorithm_forbidden(cert, {"algorithms": ["dsa", "md5"]})

        assert result.passed is False
        assert "forbidden" in result.message.lower()


class TestComplianceCheckerExpiryWarning:
    """Test cases for expiry warning compliance checks."""

    def test_expiry_passes_when_not_expiring_soon(self):
        """Test that expiry check passes when certificate is not expiring soon."""
        cert = _create_mock_certificate(days_remaining=60)
        result = ComplianceChecker._check_expiry_warning(cert, {"warning_days": 30})

        assert result.passed is True

    def test_expiry_fails_when_expiring_soon(self):
        """Test that expiry check fails when certificate is expiring soon."""
        cert = _create_mock_certificate(days_remaining=20)
        result = ComplianceChecker._check_expiry_warning(cert, {"warning_days": 30})

        assert result.passed is False
        assert "expires in" in result.message.lower()

    def test_expiry_fails_when_expired(self):
        """Test that expiry check fails when certificate is expired."""
        cert = _create_mock_certificate(days_remaining=-5)
        result = ComplianceChecker._check_expiry_warning(cert, {"warning_days": 30})

        assert result.passed is False
        assert "expired" in result.message.lower()

    def test_expiry_fails_when_days_remaining_is_none(self):
        """Test that expiry check fails when days_remaining is None."""
        cert = _create_mock_certificate(days_remaining=None)
        result = ComplianceChecker._check_expiry_warning(cert, {"warning_days": 30})

        assert result.passed is False
        assert "not set" in result.message.lower()


class TestComplianceCheckerChainRequired:
    """Test cases for chain required compliance checks."""

    def test_chain_passes_when_present(self):
        """Test that chain check passes when chain is present."""
        cert = _create_mock_certificate(issuer_chain="-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----")
        result = ComplianceChecker._check_chain_required(cert, {})

        assert result.passed is True
        assert "present" in result.message.lower()

    def test_chain_fails_when_missing(self):
        """Test that chain check fails when chain is missing."""
        cert = _create_mock_certificate(issuer_chain="")
        result = ComplianceChecker._check_chain_required(cert, {})

        assert result.passed is False
        assert "missing" in result.message.lower()

    def test_chain_fails_when_whitespace_only(self):
        """Test that chain check fails when chain is whitespace only."""
        cert = _create_mock_certificate(issuer_chain="   \n\t  ")
        result = ComplianceChecker._check_chain_required(cert, {})

        assert result.passed is False


class TestComplianceCheckerSANRequired:
    """Test cases for SAN required compliance checks."""

    def test_san_passes_when_present(self):
        """Test that SAN check passes when SANs are present."""
        cert = _create_mock_certificate(sans=["example.com", "www.example.com"])
        result = ComplianceChecker._check_san_required(cert, {"min_count": 1})

        assert result.passed is True

    def test_san_fails_when_missing(self):
        """Test that SAN check fails when SANs are missing."""
        cert = _create_mock_certificate(sans=[])
        result = ComplianceChecker._check_san_required(cert, {"min_count": 1})

        assert result.passed is False

    def test_san_passes_with_multiple(self):
        """Test that SAN check passes with multiple SANs when requiring multiple."""
        cert = _create_mock_certificate(sans=["example.com", "www.example.com", "api.example.com"])
        result = ComplianceChecker._check_san_required(cert, {"min_count": 2})

        assert result.passed is True

    def test_san_handles_none(self):
        """Test that SAN check handles None sans gracefully."""
        cert = _create_mock_certificate(sans=None)
        result = ComplianceChecker._check_san_required(cert, {"min_count": 1})

        assert result.passed is False


class TestComplianceCheckerWildcardForbidden:
    """Test cases for wildcard forbidden compliance checks."""

    def test_wildcard_passes_without_wildcards(self):
        """Test that wildcard check passes when no wildcards present."""
        cert = _create_mock_certificate(
            common_name="example.com",
            sans=["example.com", "www.example.com"],
        )
        result = ComplianceChecker._check_wildcard_forbidden(cert, {})

        assert result.passed is True
        assert "does not contain" in result.message.lower()

    def test_wildcard_fails_with_wildcard_cn(self):
        """Test that wildcard check fails with wildcard in CN."""
        cert = _create_mock_certificate(
            common_name="*.example.com",
            sans=["example.com"],
        )
        result = ComplianceChecker._check_wildcard_forbidden(cert, {})

        assert result.passed is False
        assert "*.example.com" in result.message

    def test_wildcard_fails_with_wildcard_san(self):
        """Test that wildcard check fails with wildcard in SAN."""
        cert = _create_mock_certificate(
            common_name="example.com",
            sans=["example.com", "*.example.com"],
        )
        result = ComplianceChecker._check_wildcard_forbidden(cert, {})

        assert result.passed is False
        assert "*.example.com" in result.message


class TestComplianceCheckerIssuer:
    """Test cases for issuer compliance checks."""

    def test_issuer_allowed_passes_with_allowed_issuer(self):
        """Test that allowed issuer check passes with allowed issuer."""
        cert = _create_mock_certificate(issuer="CN=DigiCert SHA2 Extended Validation Server CA")
        result = ComplianceChecker._check_issuer_allowed(cert, {"issuers": ["DigiCert", "Let's Encrypt"]})

        assert result.passed is True
        assert "matches" in result.message.lower()

    def test_issuer_allowed_fails_with_disallowed_issuer(self):
        """Test that allowed issuer check fails with disallowed issuer."""
        cert = _create_mock_certificate(issuer="CN=Unknown CA, O=Sketchy Corp")
        result = ComplianceChecker._check_issuer_allowed(cert, {"issuers": ["DigiCert", "Let's Encrypt"]})

        assert result.passed is False
        assert "not in allowed" in result.message.lower()

    def test_issuer_allowed_passes_when_no_issuers_specified(self):
        """Test that allowed issuer check passes when no issuers specified."""
        cert = _create_mock_certificate(issuer="CN=Any CA")
        result = ComplianceChecker._check_issuer_allowed(cert, {"issuers": []})

        assert result.passed is True
        assert "all allowed" in result.message.lower()

    def test_issuer_forbidden_passes_without_forbidden_issuer(self):
        """Test that forbidden issuer check passes without forbidden issuer."""
        cert = _create_mock_certificate(issuer="CN=DigiCert SHA2 Extended Validation Server CA")
        result = ComplianceChecker._check_issuer_forbidden(cert, {"issuers": ["Unknown CA", "Self-Signed"]})

        assert result.passed is True

    def test_issuer_forbidden_fails_with_forbidden_issuer(self):
        """Test that forbidden issuer check fails with forbidden issuer."""
        cert = _create_mock_certificate(issuer="CN=Self-Signed Certificate")
        result = ComplianceChecker._check_issuer_forbidden(cert, {"issuers": ["Unknown CA", "Self-Signed"]})

        assert result.passed is False
        assert "forbidden" in result.message.lower()


class TestCheckResult:
    """Test cases for CheckResult dataclass."""

    def test_check_result_creation(self):
        """Test creating a CheckResult."""
        result = CheckResult(
            passed=True,
            message="Test passed",
            checked_value="actual",
            expected_value="expected",
        )

        assert result.passed is True
        assert result.message == "Test passed"
        assert result.checked_value == "actual"
        assert result.expected_value == "expected"

    def test_check_result_defaults(self):
        """Test CheckResult default values."""
        result = CheckResult(passed=False, message="Test failed")

        assert result.passed is False
        assert result.checked_value == ""
        assert result.expected_value == ""


class TestComplianceScoreCalculation:
    """Test cases for compliance score calculation."""

    def test_score_calculation_all_pass(self):
        """Test score calculation when all checks pass."""
        passed = 10
        total = 10
        score = (passed / total * 100) if total > 0 else 0

        assert score == 100.0

    def test_score_calculation_all_fail(self):
        """Test score calculation when all checks fail."""
        passed = 0
        total = 10
        score = (passed / total * 100) if total > 0 else 0

        assert score == 0.0

    def test_score_calculation_partial(self):
        """Test score calculation with partial pass."""
        passed = 7
        total = 10
        score = (passed / total * 100) if total > 0 else 0

        assert score == 70.0

    def test_score_calculation_no_checks(self):
        """Test score calculation with no checks."""
        passed = 0
        total = 0
        score = (passed / total * 100) if total > 0 else 0

        assert score == 0


class TestComplianceIntegrationScenarios:
    """Integration test scenarios for compliance workflows."""

    def test_full_compliance_workflow(self):
        """Test complete compliance check workflow using actual checker methods."""
        cert = _create_mock_certificate(
            common_name="example.com",
            key_size=4096,
            algorithm="rsa",
            days_remaining=60,
            issuer="CN=DigiCert SHA2 Extended Validation Server CA",
            sans=["example.com", "www.example.com"],
            issuer_chain="-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
        )

        # Run actual check methods
        checks = [
            ComplianceChecker._check_min_key_size(cert, {"min_bits": 2048}),
            ComplianceChecker._check_algorithm_allowed(cert, {"algorithms": ["rsa", "ecdsa"]}),
            ComplianceChecker._check_expiry_warning(cert, {"warning_days": 30}),
        ]

        # All checks should pass for this certificate
        assert all(check.passed for check in checks)
        assert len(checks) == 3

    def test_non_compliant_certificate(self):
        """Test compliance check workflow for non-compliant certificate."""
        cert = _create_mock_certificate(
            common_name="*.example.com",  # Wildcard
            key_size=1024,  # Too small
            algorithm="dsa",  # Not allowed
            days_remaining=10,  # Expiring soon
        )

        checks = [
            ComplianceChecker._check_min_key_size(cert, {"min_bits": 2048}),
            ComplianceChecker._check_algorithm_allowed(cert, {"algorithms": ["rsa", "ecdsa"]}),
            ComplianceChecker._check_expiry_warning(cert, {"warning_days": 30}),
            ComplianceChecker._check_wildcard_forbidden(cert, {}),
        ]

        # All checks should fail for this certificate
        assert not any(check.passed for check in checks)
        assert len(checks) == 4
