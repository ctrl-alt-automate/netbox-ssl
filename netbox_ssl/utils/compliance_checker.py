"""
Compliance checker utility for validating certificates against policies.

This module provides the logic for running compliance checks against
certificates based on defined compliance policies.
"""

from dataclasses import dataclass
from datetime import date
from typing import Optional

from django.utils import timezone


@dataclass
class CheckResult:
    """Result of a single compliance check."""

    passed: bool
    message: str
    checked_value: str = ""
    expected_value: str = ""


class ComplianceChecker:
    """
    Utility class for running compliance checks on certificates.

    Provides methods for checking certificates against various policy types
    and returning detailed results.
    """

    @classmethod
    def check_certificate(cls, certificate, policy) -> CheckResult:
        """
        Run a compliance check on a certificate against a policy.

        Args:
            certificate: The Certificate instance to check
            policy: The CompliancePolicy instance to apply

        Returns:
            CheckResult with pass/fail status and details
        """
        # Import here to avoid circular imports
        from ..models import CompliancePolicyTypeChoices

        # Map policy types to check methods
        check_methods = {
            CompliancePolicyTypeChoices.TYPE_MIN_KEY_SIZE: cls._check_min_key_size,
            CompliancePolicyTypeChoices.TYPE_MAX_VALIDITY_DAYS: cls._check_max_validity_days,
            CompliancePolicyTypeChoices.TYPE_ALGORITHM_ALLOWED: cls._check_algorithm_allowed,
            CompliancePolicyTypeChoices.TYPE_ALGORITHM_FORBIDDEN: cls._check_algorithm_forbidden,
            CompliancePolicyTypeChoices.TYPE_EXPIRY_WARNING: cls._check_expiry_warning,
            CompliancePolicyTypeChoices.TYPE_CHAIN_REQUIRED: cls._check_chain_required,
            CompliancePolicyTypeChoices.TYPE_SAN_REQUIRED: cls._check_san_required,
            CompliancePolicyTypeChoices.TYPE_WILDCARD_FORBIDDEN: cls._check_wildcard_forbidden,
            CompliancePolicyTypeChoices.TYPE_ISSUER_ALLOWED: cls._check_issuer_allowed,
            CompliancePolicyTypeChoices.TYPE_ISSUER_FORBIDDEN: cls._check_issuer_forbidden,
        }

        check_method = check_methods.get(policy.policy_type)
        if not check_method:
            return CheckResult(
                passed=False,
                message=f"Unknown policy type: {policy.policy_type}",
            )

        try:
            return check_method(certificate, policy.parameters)
        except Exception as e:
            return CheckResult(
                passed=False,
                message=f"Error during check: {str(e)}",
            )

    @classmethod
    def _check_min_key_size(cls, certificate, parameters: dict) -> CheckResult:
        """Check if certificate key size meets minimum requirement."""
        min_bits = parameters.get("min_bits", 2048)
        actual_size = certificate.key_size

        if actual_size is None:
            return CheckResult(
                passed=False,
                message="Certificate key size is not set",
                checked_value="None",
                expected_value=f">= {min_bits} bits",
            )

        if actual_size >= min_bits:
            return CheckResult(
                passed=True,
                message=f"Key size {actual_size} bits meets minimum requirement of {min_bits} bits",
                checked_value=f"{actual_size} bits",
                expected_value=f">= {min_bits} bits",
            )

        return CheckResult(
            passed=False,
            message=f"Key size {actual_size} bits is below minimum requirement of {min_bits} bits",
            checked_value=f"{actual_size} bits",
            expected_value=f">= {min_bits} bits",
        )

    @classmethod
    def _check_max_validity_days(cls, certificate, parameters: dict) -> CheckResult:
        """Check if certificate validity period exceeds maximum."""
        max_days = parameters.get("max_days", 397)  # Default: 13 months (industry standard)

        if not certificate.valid_from or not certificate.valid_to:
            return CheckResult(
                passed=False,
                message="Certificate validity dates are not set",
                checked_value="None",
                expected_value=f"<= {max_days} days",
            )

        validity_period = (certificate.valid_to - certificate.valid_from).days

        if validity_period <= max_days:
            return CheckResult(
                passed=True,
                message=f"Validity period of {validity_period} days is within limit of {max_days} days",
                checked_value=f"{validity_period} days",
                expected_value=f"<= {max_days} days",
            )

        return CheckResult(
            passed=False,
            message=f"Validity period of {validity_period} days exceeds maximum of {max_days} days",
            checked_value=f"{validity_period} days",
            expected_value=f"<= {max_days} days",
        )

    @classmethod
    def _check_algorithm_allowed(cls, certificate, parameters: dict) -> CheckResult:
        """Check if certificate uses an allowed algorithm."""
        allowed = parameters.get("algorithms", ["rsa", "ecdsa", "ed25519"])
        actual = certificate.algorithm.lower() if certificate.algorithm else ""

        if actual in [a.lower() for a in allowed]:
            return CheckResult(
                passed=True,
                message=f"Algorithm '{actual}' is in allowed list: {allowed}",
                checked_value=actual,
                expected_value=f"one of {allowed}",
            )

        return CheckResult(
            passed=False,
            message=f"Algorithm '{actual}' is not in allowed list: {allowed}",
            checked_value=actual,
            expected_value=f"one of {allowed}",
        )

    @classmethod
    def _check_algorithm_forbidden(cls, certificate, parameters: dict) -> CheckResult:
        """Check if certificate uses a forbidden algorithm."""
        forbidden = parameters.get("algorithms", [])
        actual = certificate.algorithm.lower() if certificate.algorithm else ""

        if actual in [a.lower() for a in forbidden]:
            return CheckResult(
                passed=False,
                message=f"Algorithm '{actual}' is in forbidden list: {forbidden}",
                checked_value=actual,
                expected_value=f"not one of {forbidden}",
            )

        return CheckResult(
            passed=True,
            message=f"Algorithm '{actual}' is not in forbidden list",
            checked_value=actual,
            expected_value=f"not one of {forbidden}",
        )

    @classmethod
    def _check_expiry_warning(cls, certificate, parameters: dict) -> CheckResult:
        """Check if certificate is expiring within warning threshold."""
        warning_days = parameters.get("warning_days", 30)
        days_remaining = certificate.days_remaining

        if days_remaining is None:
            return CheckResult(
                passed=False,
                message="Certificate expiry date is not set",
                checked_value="None",
                expected_value=f"> {warning_days} days",
            )

        if days_remaining < 0:
            return CheckResult(
                passed=False,
                message=f"Certificate expired {abs(days_remaining)} days ago",
                checked_value=f"expired {abs(days_remaining)} days",
                expected_value=f"> {warning_days} days remaining",
            )

        if days_remaining > warning_days:
            return CheckResult(
                passed=True,
                message=f"Certificate has {days_remaining} days remaining (threshold: {warning_days})",
                checked_value=f"{days_remaining} days",
                expected_value=f"> {warning_days} days",
            )

        return CheckResult(
            passed=False,
            message=f"Certificate expires in {days_remaining} days (threshold: {warning_days})",
            checked_value=f"{days_remaining} days",
            expected_value=f"> {warning_days} days",
        )

    @classmethod
    def _check_chain_required(cls, certificate, parameters: dict) -> CheckResult:
        """Check if certificate has a certificate chain."""
        has_chain = bool(certificate.issuer_chain and certificate.issuer_chain.strip())

        if has_chain:
            # Count certificates in chain
            chain_count = certificate.issuer_chain.count("-----BEGIN CERTIFICATE-----")
            return CheckResult(
                passed=True,
                message=f"Certificate chain is present with {chain_count} certificate(s)",
                checked_value=f"{chain_count} certificates",
                expected_value="chain present",
            )

        return CheckResult(
            passed=False,
            message="Certificate chain is missing",
            checked_value="no chain",
            expected_value="chain present",
        )

    @classmethod
    def _check_san_required(cls, certificate, parameters: dict) -> CheckResult:
        """Check if certificate has Subject Alternative Names."""
        min_count = parameters.get("min_count", 1)
        sans = certificate.sans or []

        if len(sans) >= min_count:
            return CheckResult(
                passed=True,
                message=f"Certificate has {len(sans)} SAN(s) (minimum: {min_count})",
                checked_value=f"{len(sans)} SANs",
                expected_value=f">= {min_count} SANs",
            )

        return CheckResult(
            passed=False,
            message=f"Certificate has {len(sans)} SAN(s), minimum required: {min_count}",
            checked_value=f"{len(sans)} SANs",
            expected_value=f">= {min_count} SANs",
        )

    @classmethod
    def _check_wildcard_forbidden(cls, certificate, parameters: dict) -> CheckResult:
        """Check if certificate contains wildcard domains."""
        # Check common name
        cn_has_wildcard = certificate.common_name and certificate.common_name.startswith("*.")

        # Check SANs
        sans = certificate.sans or []
        wildcard_sans = [san for san in sans if san.startswith("*.")]

        if cn_has_wildcard or wildcard_sans:
            wildcards = []
            if cn_has_wildcard:
                wildcards.append(certificate.common_name)
            wildcards.extend(wildcard_sans)

            return CheckResult(
                passed=False,
                message=f"Certificate contains wildcard domain(s): {wildcards}",
                checked_value=", ".join(wildcards),
                expected_value="no wildcards",
            )

        return CheckResult(
            passed=True,
            message="Certificate does not contain wildcard domains",
            checked_value="no wildcards",
            expected_value="no wildcards",
        )

    @classmethod
    def _check_issuer_allowed(cls, certificate, parameters: dict) -> CheckResult:
        """Check if certificate issuer is in allowed list."""
        allowed_issuers = parameters.get("issuers", [])
        actual_issuer = certificate.issuer or ""

        if not allowed_issuers:
            return CheckResult(
                passed=True,
                message="No allowed issuers specified (all allowed)",
                checked_value=actual_issuer,
                expected_value="any",
            )

        # Check if any allowed issuer pattern matches
        issuer_lower = actual_issuer.lower()
        for allowed in allowed_issuers:
            if allowed.lower() in issuer_lower:
                return CheckResult(
                    passed=True,
                    message=f"Issuer matches allowed pattern: {allowed}",
                    checked_value=actual_issuer[:100],
                    expected_value=f"contains one of {allowed_issuers}",
                )

        return CheckResult(
            passed=False,
            message=f"Issuer '{actual_issuer[:50]}...' not in allowed list",
            checked_value=actual_issuer[:100],
            expected_value=f"contains one of {allowed_issuers}",
        )

    @classmethod
    def _check_issuer_forbidden(cls, certificate, parameters: dict) -> CheckResult:
        """Check if certificate issuer is in forbidden list."""
        forbidden_issuers = parameters.get("issuers", [])
        actual_issuer = certificate.issuer or ""

        if not forbidden_issuers:
            return CheckResult(
                passed=True,
                message="No forbidden issuers specified",
                checked_value=actual_issuer,
                expected_value="any",
            )

        # Check if any forbidden issuer pattern matches
        issuer_lower = actual_issuer.lower()
        for forbidden in forbidden_issuers:
            if forbidden.lower() in issuer_lower:
                return CheckResult(
                    passed=False,
                    message=f"Issuer matches forbidden pattern: {forbidden}",
                    checked_value=actual_issuer[:100],
                    expected_value=f"not contains {forbidden_issuers}",
                )

        return CheckResult(
            passed=True,
            message="Issuer is not in forbidden list",
            checked_value=actual_issuer[:100],
            expected_value=f"not contains {forbidden_issuers}",
        )

    @classmethod
    def run_all_checks(cls, certificate, policies=None):
        """
        Run all enabled compliance checks on a certificate.

        Args:
            certificate: The Certificate instance to check
            policies: Optional queryset of policies (defaults to all enabled)

        Returns:
            List of (policy, CheckResult) tuples
        """
        from ..models import CompliancePolicy

        if policies is None:
            # Get all enabled policies, filtering by tenant if applicable
            policies = CompliancePolicy.objects.filter(enabled=True)

            if certificate.tenant:
                # Include global policies (no tenant) and tenant-specific policies
                policies = policies.filter(models.Q(tenant__isnull=True) | models.Q(tenant=certificate.tenant))
            else:
                # Only include global policies for certificates without tenant
                policies = policies.filter(tenant__isnull=True)

        results = []
        for policy in policies:
            result = cls.check_certificate(certificate, policy)
            results.append((policy, result))

        return results

    @classmethod
    def save_check_results(cls, certificate, results):
        """
        Save compliance check results to the database.

        Args:
            certificate: The Certificate instance that was checked
            results: List of (policy, CheckResult) tuples

        Returns:
            List of saved ComplianceCheck instances
        """
        from ..models import ComplianceCheck, ComplianceResultChoices

        saved_checks = []
        for policy, result in results:
            # Determine result status
            if result.passed:
                status = ComplianceResultChoices.RESULT_PASS
            else:
                status = ComplianceResultChoices.RESULT_FAIL

            # Update or create the check record
            check, created = ComplianceCheck.objects.update_or_create(
                certificate=certificate,
                policy=policy,
                defaults={
                    "result": status,
                    "message": result.message,
                    "checked_value": result.checked_value[:255] if result.checked_value else "",
                    "expected_value": result.expected_value[:255] if result.expected_value else "",
                },
            )
            saved_checks.append(check)

        return saved_checks
