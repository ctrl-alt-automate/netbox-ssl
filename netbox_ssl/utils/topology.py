"""
Certificate topology builder for certificate map visualization.

Builds a tree structure: Tenant -> Device/VM -> Service -> Certificate(s)
with expiry color coding.
"""

from __future__ import annotations

from typing import Any

from django.contrib.contenttypes.models import ContentType


def _expiry_color(days_remaining: int | None) -> str:
    """Return CSS color class based on days remaining."""
    if days_remaining is None or days_remaining < 0:
        return "danger"
    if days_remaining < 14:
        return "danger"
    if days_remaining < 30:
        return "warning"
    return "success"


class CertificateTopologyBuilder:
    """Build topology tree for certificate map visualization."""

    def __init__(self) -> None:
        from netbox_ssl.models import Certificate, CertificateAssignment

        self.Certificate = Certificate
        self.CertificateAssignment = CertificateAssignment

    def build_tree(
        self,
        tenant: Any | None = None,
        status_filter: str | None = None,
        ca_filter: int | None = None,
    ) -> list[dict[str, Any]]:
        """
        Build topology tree grouped by tenant.

        Returns list of tenant nodes, each containing devices/VMs
        with their services and assigned certificates.
        """
        # Fetch all relevant assignments with batch lookups
        assignments_qs = self.CertificateAssignment.objects.select_related(
            "certificate",
            "certificate__tenant",
            "certificate__issuing_ca",
            "assigned_object_type",
        )

        if tenant is not None:
            assignments_qs = assignments_qs.filter(certificate__tenant=tenant)
        if status_filter:
            assignments_qs = assignments_qs.filter(certificate__status=status_filter)
        if ca_filter:
            assignments_qs = assignments_qs.filter(certificate__issuing_ca_id=ca_filter)

        # Batch-resolve GenericForeignKey objects per ContentType
        assignments = list(assignments_qs)
        resolved_objects = self._batch_resolve_gfk(assignments)

        # Build tree: tenant -> device/VM -> service -> certificates
        tree: dict[str | None, dict] = {}

        for assignment in assignments:
            cert = assignment.certificate
            tenant_obj = cert.tenant
            tenant_key = tenant_obj.pk if tenant_obj else None
            tenant_name = tenant_obj.name if tenant_obj else "No Tenant"

            if tenant_key not in tree:
                tree[tenant_key] = {
                    "tenant": {
                        "id": tenant_key,
                        "name": tenant_name,
                        "url": tenant_obj.get_absolute_url() if tenant_obj else None,
                    },
                    "devices": {},
                }

            # Resolve the assigned object
            obj_key = (assignment.assigned_object_type_id, assignment.assigned_object_id)
            assigned_obj = resolved_objects.get(obj_key)
            if assigned_obj is None:
                continue

            device_name = str(assigned_obj)
            device_key = f"{assignment.assigned_object_type_id}:{assignment.assigned_object_id}"

            if device_key not in tree[tenant_key]["devices"]:
                obj_url = getattr(assigned_obj, "get_absolute_url", lambda: None)()
                obj_type = assignment.assigned_object_type.model if assignment.assigned_object_type else "unknown"

                # For services, resolve the parent device/VM
                parent_name = None
                parent_url = None
                if obj_type == "service":
                    parent = getattr(assigned_obj, "parent", None)
                    if parent is not None:
                        parent_name = str(parent)
                        parent_url = getattr(parent, "get_absolute_url", lambda: None)()

                tree[tenant_key]["devices"][device_key] = {
                    "name": device_name,
                    "url": obj_url,
                    "type": obj_type,
                    "parent_name": parent_name,
                    "parent_url": parent_url,
                    "certificates": [],
                }

            days = cert.days_remaining if hasattr(cert, "days_remaining") else None
            tree[tenant_key]["devices"][device_key]["certificates"].append(
                {
                    "id": cert.pk,
                    "common_name": cert.common_name,
                    "url": cert.get_absolute_url(),
                    "status": cert.status,
                    "valid_to": cert.valid_to,
                    "days_remaining": days,
                    "color": _expiry_color(days),
                    "is_primary": getattr(assignment, "is_primary", False),
                }
            )

        # Also add orphan certificates (no assignments)
        orphan_qs = self.Certificate.objects.filter(status="active").exclude(
            pk__in=[a.certificate_id for a in assignments]
        )
        if tenant is not None:
            orphan_qs = orphan_qs.filter(tenant=tenant)
        if status_filter:
            orphan_qs = orphan_qs.filter(status=status_filter)
        if ca_filter:
            orphan_qs = orphan_qs.filter(issuing_ca_id=ca_filter)

        orphans = list(orphan_qs.select_related("tenant")[:100])
        if orphans:
            orphan_tenant_key = "__orphans__"
            tree[orphan_tenant_key] = {
                "tenant": {"id": None, "name": "Unassigned Certificates", "url": None},
                "devices": {
                    "__orphan__": {
                        "name": "No Assignment",
                        "url": None,
                        "type": "orphan",
                        "certificates": [],
                    }
                },
            }
            for cert in orphans:
                days = cert.days_remaining if hasattr(cert, "days_remaining") else None
                tree[orphan_tenant_key]["devices"]["__orphan__"]["certificates"].append(
                    {
                        "id": cert.pk,
                        "common_name": cert.common_name,
                        "url": cert.get_absolute_url(),
                        "status": cert.status,
                        "valid_to": cert.valid_to,
                        "days_remaining": days,
                        "color": _expiry_color(days),
                        "is_primary": False,
                    }
                )

        # Convert to list format
        result = []
        for tenant_data in tree.values():
            tenant_node = {
                "tenant": tenant_data["tenant"],
                "devices": list(tenant_data["devices"].values()),
            }
            # Sort devices by name
            tenant_node["devices"].sort(key=lambda d: d["name"])
            result.append(tenant_node)

        # Sort tenants: named tenants first, then "No Tenant", then orphans
        result.sort(key=lambda t: (t["tenant"]["id"] is None, t["tenant"]["name"]))
        return result

    def _batch_resolve_gfk(self, assignments: list) -> dict[tuple[int, int], Any]:
        """Batch-resolve GenericForeignKey objects to avoid N+1 queries."""
        # Group by content type
        ct_groups: dict[int, list[int]] = {}
        for assignment in assignments:
            ct_id = assignment.assigned_object_type_id
            obj_id = assignment.assigned_object_id
            if ct_id is not None and obj_id is not None:
                ct_groups.setdefault(ct_id, []).append(obj_id)

        # Batch fetch per content type
        resolved: dict[tuple[int, int], Any] = {}
        for ct_id, obj_ids in ct_groups.items():
            try:
                ct = ContentType.objects.get_for_id(ct_id)
                model_class = ct.model_class()
                if model_class is not None:
                    objects = model_class.objects.filter(pk__in=set(obj_ids))
                    for obj in objects:
                        resolved[(ct_id, obj.pk)] = obj
            except Exception:
                continue

        return resolved
