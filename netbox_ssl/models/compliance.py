"""
Compliance reporting models for certificate policy enforcement.

This module provides models for defining compliance policies and tracking
compliance check results against certificates.
"""

from django.db import models
from django.urls import reverse
from django.utils import timezone
from netbox.models import NetBoxModel
from utilities.choices import ChoiceSet


class CompliancePolicyTypeChoices(ChoiceSet):
    """Types of compliance checks that can be performed."""

    TYPE_MIN_KEY_SIZE = "min_key_size"
    TYPE_MAX_VALIDITY_DAYS = "max_validity_days"
    TYPE_ALGORITHM_ALLOWED = "algorithm_allowed"
    TYPE_ALGORITHM_FORBIDDEN = "algorithm_forbidden"
    TYPE_EXPIRY_WARNING = "expiry_warning"
    TYPE_CHAIN_REQUIRED = "chain_required"
    TYPE_SAN_REQUIRED = "san_required"
    TYPE_WILDCARD_FORBIDDEN = "wildcard_forbidden"
    TYPE_ISSUER_ALLOWED = "issuer_allowed"
    TYPE_ISSUER_FORBIDDEN = "issuer_forbidden"

    CHOICES = [
        (TYPE_MIN_KEY_SIZE, "Minimum Key Size", "blue"),
        (TYPE_MAX_VALIDITY_DAYS, "Maximum Validity Period", "cyan"),
        (TYPE_ALGORITHM_ALLOWED, "Algorithm Allowed", "green"),
        (TYPE_ALGORITHM_FORBIDDEN, "Algorithm Forbidden", "red"),
        (TYPE_EXPIRY_WARNING, "Expiry Warning Threshold", "yellow"),
        (TYPE_CHAIN_REQUIRED, "Chain Required", "purple"),
        (TYPE_SAN_REQUIRED, "SAN Required", "orange"),
        (TYPE_WILDCARD_FORBIDDEN, "Wildcard Forbidden", "pink"),
        (TYPE_ISSUER_ALLOWED, "Issuer Allowed", "teal"),
        (TYPE_ISSUER_FORBIDDEN, "Issuer Forbidden", "gray"),
    ]


class ComplianceSeverityChoices(ChoiceSet):
    """Severity levels for compliance violations."""

    SEVERITY_CRITICAL = "critical"
    SEVERITY_WARNING = "warning"
    SEVERITY_INFO = "info"

    CHOICES = [
        (SEVERITY_CRITICAL, "Critical", "red"),
        (SEVERITY_WARNING, "Warning", "yellow"),
        (SEVERITY_INFO, "Info", "blue"),
    ]


class ComplianceResultChoices(ChoiceSet):
    """Result status for compliance checks."""

    RESULT_PASS = "pass"
    RESULT_FAIL = "fail"
    RESULT_ERROR = "error"
    RESULT_SKIPPED = "skipped"

    CHOICES = [
        (RESULT_PASS, "Pass", "green"),
        (RESULT_FAIL, "Fail", "red"),
        (RESULT_ERROR, "Error", "orange"),
        (RESULT_SKIPPED, "Skipped", "gray"),
    ]


class CompliancePolicy(NetBoxModel):
    """
    A compliance policy defining rules for certificate validation.

    Policies define specific checks that should be applied to certificates
    to ensure they meet organizational security requirements.
    """

    name = models.CharField(
        max_length=100,
        unique=True,
        help_text="Unique name for this compliance policy",
    )
    description = models.TextField(
        blank=True,
        help_text="Detailed description of the policy",
    )
    policy_type = models.CharField(
        max_length=30,
        choices=CompliancePolicyTypeChoices,
        help_text="Type of compliance check",
    )
    severity = models.CharField(
        max_length=20,
        choices=ComplianceSeverityChoices,
        default=ComplianceSeverityChoices.SEVERITY_WARNING,
        help_text="Severity level when policy is violated",
    )
    enabled = models.BooleanField(
        default=True,
        help_text="Whether this policy is active",
    )

    # Policy parameters (flexible JSON storage for different policy types)
    # Examples:
    # - min_key_size: {"min_bits": 2048}
    # - algorithm_allowed: {"algorithms": ["rsa", "ecdsa"]}
    # - algorithm_forbidden: {"algorithms": ["rsa"]}
    # - max_validity_days: {"max_days": 397}
    # - expiry_warning: {"warning_days": 30}
    # - issuer_allowed: {"issuers": ["DigiCert", "Let's Encrypt"]}
    # - issuer_forbidden: {"issuers": ["Unknown CA"]}
    parameters = models.JSONField(
        default=dict,
        blank=True,
        help_text="Policy parameters as JSON (varies by policy type)",
    )

    # Optional tenant scoping
    tenant = models.ForeignKey(
        to="tenancy.Tenant",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="compliance_policies",
        help_text="Limit policy to specific tenant (null = global)",
    )

    class Meta:
        ordering = ["name"]
        verbose_name_plural = "compliance policies"

    def __str__(self):
        return f"{self.name} ({self.get_policy_type_display()})"

    def get_absolute_url(self):
        return reverse("plugins:netbox_ssl:compliancepolicy", args=[self.pk])

    def get_parameter(self, key, default=None):
        """Get a specific parameter value."""
        return self.parameters.get(key, default)


class ComplianceCheck(NetBoxModel):
    """
    Result of a compliance check against a certificate.

    Stores the outcome of running a compliance policy against a specific
    certificate, including pass/fail status and detailed messages.
    """

    certificate = models.ForeignKey(
        to="netbox_ssl.Certificate",
        on_delete=models.CASCADE,
        related_name="compliance_checks",
        help_text="Certificate that was checked",
    )
    policy = models.ForeignKey(
        to=CompliancePolicy,
        on_delete=models.CASCADE,
        related_name="checks",
        help_text="Policy that was applied",
    )
    result = models.CharField(
        max_length=20,
        choices=ComplianceResultChoices,
        help_text="Result of the compliance check",
    )
    message = models.TextField(
        blank=True,
        help_text="Detailed message about the check result",
    )
    checked_at = models.DateTimeField(
        default=timezone.now,
        help_text="When the check was performed",
    )
    checked_value = models.CharField(
        max_length=255,
        blank=True,
        help_text="The actual value that was checked",
    )
    expected_value = models.CharField(
        max_length=255,
        blank=True,
        help_text="The expected value per policy",
    )

    class Meta:
        ordering = ["-checked_at"]
        # Only keep the latest check per certificate-policy combination
        constraints = [
            models.UniqueConstraint(
                fields=["certificate", "policy"],
                name="unique_certificate_policy_check",
            ),
        ]

    def __str__(self):
        return f"{self.certificate.common_name} - {self.policy.name}: {self.result}"

    def get_absolute_url(self):
        return reverse("plugins:netbox_ssl:compliancecheck", args=[self.pk])

    @property
    def is_passing(self):
        """Check if this result is a pass."""
        return self.result == ComplianceResultChoices.RESULT_PASS

    @property
    def is_failing(self):
        """Check if this result is a fail."""
        return self.result == ComplianceResultChoices.RESULT_FAIL

    @property
    def severity(self):
        """Get the severity from the associated policy."""
        return self.policy.severity
