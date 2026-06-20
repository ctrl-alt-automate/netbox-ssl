"""Models for website-centric certificate monitoring (#149)."""

from django.contrib.contenttypes.fields import GenericForeignKey
from django.db import models
from django.urls import reverse
from netbox.models import NetBoxModel
from utilities.choices import ChoiceSet


class MonitoredEndpointStatusChoices(ChoiceSet):
    STATUS_PENDING = "pending"
    STATUS_OK = "ok"
    STATUS_UNREACHABLE = "unreachable"
    STATUS_UNTRUSTED = "untrusted"

    CHOICES = [
        (STATUS_PENDING, "Pending", "gray"),
        (STATUS_OK, "OK", "green"),
        (STATUS_UNREACHABLE, "Unreachable", "red"),
        (STATUS_UNTRUSTED, "Untrusted", "orange"),
    ]


class MonitoredEndpoint(NetBoxModel):
    """A monitored website/URL whose presented certificate is tracked over time."""

    name = models.CharField(max_length=200, help_text="Human label, e.g. 'HR portal'.")
    url = models.CharField(max_length=500, help_text="https://host:port to monitor.")
    sni = models.CharField(max_length=255, blank=True, help_text="Optional SNI override (defaults to the URL host).")
    certificate = models.ForeignKey(
        to="netbox_ssl.Certificate",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="monitored_endpoints",
        help_text="The certificate this endpoint currently presents.",
    )
    assigned_object_type = models.ForeignKey(
        to="contenttypes.ContentType",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        limit_choices_to={"model__in": ["service", "device", "virtualmachine"]},
    )
    assigned_object_id = models.PositiveBigIntegerField(null=True, blank=True)
    assigned_object = GenericForeignKey(ct_field="assigned_object_type", fk_field="assigned_object_id")
    tenant = models.ForeignKey(
        to="tenancy.Tenant", on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    status = models.CharField(
        max_length=20,
        choices=MonitoredEndpointStatusChoices,
        default=MonitoredEndpointStatusChoices.STATUS_PENDING,
    )
    last_checked = models.DateTimeField(null=True, blank=True)
    last_seen = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(blank=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name

    def get_absolute_url(self) -> str:
        return reverse("plugins:netbox_ssl:monitoredendpoint", args=[self.pk])

    @property
    def days_remaining(self) -> int | None:
        return self.certificate.days_remaining if self.certificate else None


class MonitoredEndpointCertificate(models.Model):
    """Rotation history: which certificate an endpoint presented, and when."""

    endpoint = models.ForeignKey(
        to=MonitoredEndpoint, on_delete=models.CASCADE, related_name="cert_history"
    )
    certificate = models.ForeignKey(to="netbox_ssl.Certificate", on_delete=models.CASCADE)
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()

    class Meta:
        ordering = ["-last_seen"]
        constraints = [
            models.UniqueConstraint(fields=["endpoint", "certificate"], name="unique_endpoint_certificate"),
        ]

    def __str__(self) -> str:
        return f"{self.endpoint} → {self.certificate}"
