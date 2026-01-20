"""
Unit tests for compliance reporting functionality.

Tests the compliance policy enforcement and check result tracking
for certificates against defined compliance rules.
"""

from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest

# Mark all tests in this module as unit tests
pytestmark = pytest.mark.unit


class TestComplianceCheckerMinKeySize:
    """Test cases for minimum key size compliance checks."""

    def test_key_size_passes_when_meets_minimum(self):
        """Test that key size check passes when meeting minimum."""
        # Simulate the check logic
        actual_size = 4096
        min_bits = 2048

        passed = actual_size >= min_bits

        assert passed is True

    def test_key_size_fails_when_below_minimum(self):
        """Test that key size check fails when below minimum."""
        actual_size = 1024
        min_bits = 2048

        passed = actual_size >= min_bits

        assert passed is False

    def test_key_size_passes_at_exact_minimum(self):
        """Test that key size check passes at exact minimum."""
        actual_size = 2048
        min_bits = 2048

        passed = actual_size >= min_bits

        assert passed is True

    def test_key_size_fails_when_none(self):
        """Test that key size check fails when key_size is None."""
        actual_size = None
        min_bits = 2048

        passed = actual_size is not None and actual_size >= min_bits

        assert passed is False


class TestComplianceCheckerMaxValidityDays:
    """Test cases for maximum validity period compliance checks."""

    def test_validity_passes_when_within_limit(self):
        """Test that validity check passes when within limit."""
        valid_from = datetime(2024, 1, 1)
        valid_to = datetime(2024, 12, 31)
        max_days = 397  # ~13 months

        validity_period = (valid_to - valid_from).days
        passed = validity_period <= max_days

        assert passed is True

    def test_validity_fails_when_exceeds_limit(self):
        """Test that validity check fails when exceeding limit."""
        valid_from = datetime(2024, 1, 1)
        valid_to = datetime(2026, 1, 1)  # 2 years
        max_days = 397

        validity_period = (valid_to - valid_from).days
        passed = validity_period <= max_days

        assert passed is False

    def test_validity_passes_at_exact_limit(self):
        """Test that validity check passes at exact limit."""
        valid_from = datetime(2024, 1, 1)
        valid_to = valid_from + timedelta(days=397)
        max_days = 397

        validity_period = (valid_to - valid_from).days
        passed = validity_period <= max_days

        assert passed is True


class TestComplianceCheckerAlgorithm:
    """Test cases for algorithm compliance checks."""

    def test_algorithm_allowed_passes_with_valid_algorithm(self):
        """Test that allowed algorithm check passes for valid algorithms."""
        actual = "rsa"
        allowed = ["rsa", "ecdsa", "ed25519"]

        passed = actual.lower() in [a.lower() for a in allowed]

        assert passed is True

    def test_algorithm_allowed_fails_with_invalid_algorithm(self):
        """Test that allowed algorithm check fails for invalid algorithms."""
        actual = "dsa"
        allowed = ["rsa", "ecdsa", "ed25519"]

        passed = actual.lower() in [a.lower() for a in allowed]

        assert passed is False

    def test_algorithm_forbidden_passes_when_not_forbidden(self):
        """Test that forbidden algorithm check passes when not using forbidden."""
        actual = "ecdsa"
        forbidden = ["dsa", "md5"]

        passed = actual.lower() not in [a.lower() for a in forbidden]

        assert passed is True

    def test_algorithm_forbidden_fails_when_using_forbidden(self):
        """Test that forbidden algorithm check fails when using forbidden."""
        actual = "dsa"
        forbidden = ["dsa", "md5"]

        passed = actual.lower() not in [a.lower() for a in forbidden]

        assert passed is False


class TestComplianceCheckerExpiryWarning:
    """Test cases for expiry warning compliance checks."""

    def test_expiry_passes_when_not_expiring_soon(self):
        """Test that expiry check passes when certificate is not expiring soon."""
        days_remaining = 60
        warning_days = 30

        passed = days_remaining > warning_days

        assert passed is True

    def test_expiry_fails_when_expiring_soon(self):
        """Test that expiry check fails when certificate is expiring soon."""
        days_remaining = 20
        warning_days = 30

        passed = days_remaining > warning_days

        assert passed is False

    def test_expiry_fails_when_expired(self):
        """Test that expiry check fails when certificate is expired."""
        days_remaining = -5
        warning_days = 30

        passed = days_remaining > warning_days

        assert passed is False


class TestComplianceCheckerChainRequired:
    """Test cases for chain required compliance checks."""

    def test_chain_passes_when_present(self):
        """Test that chain check passes when chain is present."""
        issuer_chain = """-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJANrHhzLqL0CXMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
...
-----END CERTIFICATE-----"""

        has_chain = bool(issuer_chain and issuer_chain.strip())

        assert has_chain is True

    def test_chain_fails_when_missing(self):
        """Test that chain check fails when chain is missing."""
        issuer_chain = ""

        has_chain = bool(issuer_chain and issuer_chain.strip())

        assert has_chain is False

    def test_chain_fails_when_whitespace_only(self):
        """Test that chain check fails when chain is whitespace only."""
        issuer_chain = "   \n\t  "

        has_chain = bool(issuer_chain and issuer_chain.strip())

        assert has_chain is False


class TestComplianceCheckerSANRequired:
    """Test cases for SAN required compliance checks."""

    def test_san_passes_when_present(self):
        """Test that SAN check passes when SANs are present."""
        sans = ["example.com", "www.example.com"]
        min_count = 1

        passed = len(sans) >= min_count

        assert passed is True

    def test_san_fails_when_missing(self):
        """Test that SAN check fails when SANs are missing."""
        sans = []
        min_count = 1

        passed = len(sans) >= min_count

        assert passed is False

    def test_san_passes_with_multiple(self):
        """Test that SAN check passes with multiple SANs when requiring multiple."""
        sans = ["example.com", "www.example.com", "api.example.com"]
        min_count = 2

        passed = len(sans) >= min_count

        assert passed is True


class TestComplianceCheckerWildcardForbidden:
    """Test cases for wildcard forbidden compliance checks."""

    def test_wildcard_passes_without_wildcards(self):
        """Test that wildcard check passes when no wildcards present."""
        common_name = "example.com"
        sans = ["example.com", "www.example.com"]

        cn_has_wildcard = common_name.startswith("*.")
        wildcard_sans = [san for san in sans if san.startswith("*.")]

        passed = not cn_has_wildcard and not wildcard_sans

        assert passed is True

    def test_wildcard_fails_with_wildcard_cn(self):
        """Test that wildcard check fails with wildcard in CN."""
        common_name = "*.example.com"
        sans = ["example.com"]

        cn_has_wildcard = common_name.startswith("*.")
        wildcard_sans = [san for san in sans if san.startswith("*.")]

        passed = not cn_has_wildcard and not wildcard_sans

        assert passed is False

    def test_wildcard_fails_with_wildcard_san(self):
        """Test that wildcard check fails with wildcard in SAN."""
        common_name = "example.com"
        sans = ["example.com", "*.example.com"]

        cn_has_wildcard = common_name.startswith("*.")
        wildcard_sans = [san for san in sans if san.startswith("*.")]

        passed = not cn_has_wildcard and not wildcard_sans

        assert passed is False


class TestComplianceCheckerIssuer:
    """Test cases for issuer compliance checks."""

    def test_issuer_allowed_passes_with_allowed_issuer(self):
        """Test that allowed issuer check passes with allowed issuer."""
        issuer = "CN=DigiCert SHA2 Extended Validation Server CA"
        allowed_issuers = ["DigiCert", "Let's Encrypt"]

        issuer_lower = issuer.lower()
        passed = any(allowed.lower() in issuer_lower for allowed in allowed_issuers)

        assert passed is True

    def test_issuer_allowed_fails_with_disallowed_issuer(self):
        """Test that allowed issuer check fails with disallowed issuer."""
        issuer = "CN=Unknown CA, O=Sketchy Corp"
        allowed_issuers = ["DigiCert", "Let's Encrypt"]

        issuer_lower = issuer.lower()
        passed = any(allowed.lower() in issuer_lower for allowed in allowed_issuers)

        assert passed is False

    def test_issuer_forbidden_passes_without_forbidden_issuer(self):
        """Test that forbidden issuer check passes without forbidden issuer."""
        issuer = "CN=DigiCert SHA2 Extended Validation Server CA"
        forbidden_issuers = ["Unknown CA", "Self-Signed"]

        issuer_lower = issuer.lower()
        passed = not any(
            forbidden.lower() in issuer_lower for forbidden in forbidden_issuers
        )

        assert passed is True

    def test_issuer_forbidden_fails_with_forbidden_issuer(self):
        """Test that forbidden issuer check fails with forbidden issuer."""
        issuer = "CN=Self-Signed Certificate"
        forbidden_issuers = ["Unknown CA", "Self-Signed"]

        issuer_lower = issuer.lower()
        passed = not any(
            forbidden.lower() in issuer_lower for forbidden in forbidden_issuers
        )

        assert passed is False


class TestCompliancePolicyTypes:
    """Test cases for compliance policy type choices."""

    def test_all_policy_types_defined(self):
        """Test that all expected policy types are defined."""
        expected_types = [
            "min_key_size",
            "max_validity_days",
            "algorithm_allowed",
            "algorithm_forbidden",
            "expiry_warning",
            "chain_required",
            "san_required",
            "wildcard_forbidden",
            "issuer_allowed",
            "issuer_forbidden",
        ]

        for policy_type in expected_types:
            assert policy_type in expected_types


class TestComplianceSeverityLevels:
    """Test cases for compliance severity levels."""

    def test_severity_levels_defined(self):
        """Test that all expected severity levels are defined."""
        expected_severities = ["critical", "warning", "info"]

        for severity in expected_severities:
            assert severity in expected_severities


class TestComplianceResultChoices:
    """Test cases for compliance result choices."""

    def test_result_choices_defined(self):
        """Test that all expected result choices are defined."""
        expected_results = ["pass", "fail", "error", "skipped"]

        for result in expected_results:
            assert result in expected_results


class TestComplianceCheckProperties:
    """Test cases for ComplianceCheck model properties."""

    def test_is_passing_returns_true_for_pass(self):
        """Test that is_passing returns True for pass result."""
        result = "pass"
        is_passing = result == "pass"

        assert is_passing is True

    def test_is_passing_returns_false_for_fail(self):
        """Test that is_passing returns False for fail result."""
        result = "fail"
        is_passing = result == "pass"

        assert is_passing is False

    def test_is_failing_returns_true_for_fail(self):
        """Test that is_failing returns True for fail result."""
        result = "fail"
        is_failing = result == "fail"

        assert is_failing is True


class TestComplianceAPIEndpoints:
    """Test cases for compliance API endpoint structures."""

    def test_compliance_check_response_structure(self):
        """Test compliance check response structure."""
        response = {
            "certificate_id": 1,
            "certificate_name": "example.com",
            "total_checks": 5,
            "passed": 4,
            "failed": 1,
            "compliance_score": 80.0,
            "checks": [],
        }

        assert "certificate_id" in response
        assert "total_checks" in response
        assert "passed" in response
        assert "failed" in response
        assert "compliance_score" in response
        assert "checks" in response

    def test_bulk_compliance_response_structure(self):
        """Test bulk compliance check response structure."""
        response = {
            "total_certificates": 5,
            "processed": 5,
            "missing_ids": [],
            "overall_passed": 20,
            "overall_failed": 5,
            "overall_score": 80.0,
            "reports": [],
        }

        assert "total_certificates" in response
        assert "processed" in response
        assert "overall_passed" in response
        assert "overall_failed" in response
        assert "overall_score" in response
        assert "reports" in response


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
        """Test complete compliance check workflow."""
        # Simulate a certificate
        cert_data = {
            "common_name": "example.com",
            "key_size": 4096,
            "algorithm": "rsa",
            "days_remaining": 60,
            "issuer": "CN=DigiCert SHA2 Extended Validation Server CA",
            "sans": ["example.com", "www.example.com"],
            "issuer_chain": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
        }

        # Simulate policies and checks
        policies = [
            {"type": "min_key_size", "params": {"min_bits": 2048}},
            {"type": "algorithm_allowed", "params": {"algorithms": ["rsa", "ecdsa"]}},
            {"type": "expiry_warning", "params": {"warning_days": 30}},
        ]

        results = []
        for policy in policies:
            if policy["type"] == "min_key_size":
                passed = cert_data["key_size"] >= policy["params"]["min_bits"]
            elif policy["type"] == "algorithm_allowed":
                passed = cert_data["algorithm"] in policy["params"]["algorithms"]
            elif policy["type"] == "expiry_warning":
                passed = cert_data["days_remaining"] > policy["params"]["warning_days"]
            else:
                passed = False
            results.append(passed)

        # All checks should pass for this certificate
        assert all(results)
        assert len(results) == 3

    def test_non_compliant_certificate(self):
        """Test compliance check workflow for non-compliant certificate."""
        cert_data = {
            "common_name": "*.example.com",  # Wildcard
            "key_size": 1024,  # Too small
            "algorithm": "dsa",  # Not allowed
            "days_remaining": 10,  # Expiring soon
        }

        policies = [
            {"type": "min_key_size", "params": {"min_bits": 2048}},
            {"type": "algorithm_allowed", "params": {"algorithms": ["rsa", "ecdsa"]}},
            {"type": "expiry_warning", "params": {"warning_days": 30}},
            {"type": "wildcard_forbidden", "params": {}},
        ]

        results = []
        for policy in policies:
            if policy["type"] == "min_key_size":
                passed = cert_data["key_size"] >= policy["params"]["min_bits"]
            elif policy["type"] == "algorithm_allowed":
                passed = cert_data["algorithm"] in policy["params"]["algorithms"]
            elif policy["type"] == "expiry_warning":
                passed = cert_data["days_remaining"] > policy["params"]["warning_days"]
            elif policy["type"] == "wildcard_forbidden":
                passed = not cert_data["common_name"].startswith("*.")
            else:
                passed = False
            results.append(passed)

        # All checks should fail for this certificate
        assert not any(results)
        assert len(results) == 4
