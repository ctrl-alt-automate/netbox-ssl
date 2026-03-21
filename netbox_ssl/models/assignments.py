"""
CertificateAssignment model for linking certificates to infrastructure.

Supports assignment to Services (primary/recommended), Devices, and Virtual Machines.
Service-level assignment is preferred as it provides port-level granularity.
"""

import logging

from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.urls import reverse
from netbox.models import NetBoxModel

logger = logging.getLogger("netbox_ssl.models")


class CertificateAssignment(NetBoxModel):
    """
    Links a Certificate to an infrastructure object.

    Supported assignment targets:
    - Service (recommended): Port-level assignment (e.g., HTTPS on port 443)
    - Device: Device-level assignment
    - VirtualMachine: VM-level assignment

    Multi-tenancy: If a Certificate has a Tenant assigned, it can only be
    linked to objects belonging to the same Tenant.
    """

    certificate = models.ForeignKey(
        to="netbox_ssl.Certificate",
        on_delete=models.CASCADE,
        related_name="assignments",
        help_text="The certificate being assigned",
    )

    # Generic foreign key to support multiple target types
    assigned_object_type = models.ForeignKey(
        to=ContentType,
        on_delete=models.CASCADE,
        limit_choices_to={
            "model__in": ["service", "device", "virtualmachine"],
        },
        help_text="Type of the assigned object",
    )
    assigned_object_id = models.PositiveBigIntegerField(
        help_text="ID of the assigned object",
    )
    assigned_object = GenericForeignKey(
        ct_field="assigned_object_type",
        fk_field="assigned_object_id",
    )

    # Assignment metadata
    is_primary = models.BooleanField(
        default=True,
        help_text="Whether this is the primary certificate for the target",
    )
    notes = models.TextField(
        blank=True,
        help_text="Additional notes about this assignment",
    )

    class Meta:
        ordering = ["certificate", "assigned_object_type"]
        constraints = [
            models.UniqueConstraint(
                fields=["certificate", "assigned_object_type", "assigned_object_id"],
                name="unique_certificate_assignment",
            ),
        ]

    def __str__(self):
        return f"{self.certificate} → {self.assigned_object}"

    def get_absolute_url(self):
        return reverse("plugins:netbox_ssl:certificateassignment", args=[self.pk])

    def clean(self):
        """Validate assignment respects tenant boundaries."""
        from django.core.exceptions import ValidationError

        if not self.certificate_id or not self.assigned_object:
            return

        cert_tenant = self.certificate.tenant
        if cert_tenant is None:
            return

        # Check if assigned object has a tenant and if it matches
        obj = self.assigned_object
        obj_tenant = getattr(obj, "tenant", None)

        # For Services, check the parent device/VM tenant
        if hasattr(obj, "parent") and obj.parent:
            obj_tenant = getattr(obj.parent, "tenant", None)
        elif hasattr(obj, "device") and obj.device:
            obj_tenant = getattr(obj.device, "tenant", None)
        elif hasattr(obj, "virtual_machine") and obj.virtual_machine:
            obj_tenant = getattr(obj.virtual_machine, "tenant", None)

        if obj_tenant and obj_tenant != cert_tenant:
            raise ValidationError(
                f"Certificate belongs to tenant '{cert_tenant}', but target "
                f"belongs to tenant '{obj_tenant}'. Cross-tenant assignments "
                "are not allowed."
            )

    def save(self, *args, **kwargs):
        """Save and touch parent certificate to update its changelog."""
        super().save(*args, **kwargs)
        # Touch the parent certificate so its changelog reflects assignment changes
        if self.certificate_id:
            from django.utils import timezone

            from .certificates import Certificate

            Certificate.objects.filter(pk=self.certificate_id).update(last_updated=timezone.now())

        # Create lifecycle event for assignment
        from .lifecycle import CertificateLifecycleEvent, LifecycleEventTypeChoices

        try:
            CertificateLifecycleEvent.objects.create(
                certificate_id=self.certificate_id,
                event_type=LifecycleEventTypeChoices.EVENT_ASSIGNMENT_ADDED,
                description=f"Assigned to {self.assigned_object_type.model}: {self.assigned_object}",
            )
        except Exception as e:
            logger.warning("Failed to create lifecycle event: %s", e)

    def delete(self, *args, **kwargs):
        """Delete and touch parent certificate to update its changelog."""
        # Create lifecycle event for assignment removal (before delete)
        from .lifecycle import CertificateLifecycleEvent, LifecycleEventTypeChoices

        try:
            CertificateLifecycleEvent.objects.create(
                certificate_id=self.certificate_id,
                event_type=LifecycleEventTypeChoices.EVENT_ASSIGNMENT_REMOVED,
                description=f"Removed from {self.assigned_object_type.model}: {self.assigned_object}",
            )
        except Exception as e:
            logger.warning("Failed to create lifecycle event: %s", e)

        certificate_id = self.certificate_id
        result = super().delete(*args, **kwargs)
        # Touch the parent certificate so its changelog reflects assignment removal
        if certificate_id:
            from django.utils import timezone

            from .certificates import Certificate

            Certificate.objects.filter(pk=certificate_id).update(last_updated=timezone.now())
        return result

    @property
    def assigned_object_name(self):
        """Get a display name for the assigned object."""
        obj = self.assigned_object
        if obj is None:
            return "Unknown"
        return str(obj)

    @property
    def assigned_object_type_name(self):
        """Get the human-readable type name."""
        return self.assigned_object_type.model.replace("_", " ").title()
