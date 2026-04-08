"""
Views for Certificate model.

Includes Smart Paste import and Janus Renewal workflow views.
"""

import contextlib
from datetime import datetime

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from django.views.generic import View
from netbox.views import generic

from ..filtersets import CertificateFilterSet
from ..forms import (
    CertificateBulkEditForm,
    CertificateFilterForm,
    CertificateForm,
    CertificateImportForm,
)
from ..models import Certificate, CertificateStatusChoices
from ..tables import CertificateTable
from ..utils import (
    CertificateParseError,
    CertificateParser,
    PrivateKeyDetectedError,
    detect_issuing_ca,
)
from ..utils.bulk_parser import parse as bulk_parse


def _get_assigned_object_tenant(obj):
    if obj is None:
        return None
    if hasattr(obj, "parent") and obj.parent:
        return getattr(obj.parent, "tenant", None)
    if hasattr(obj, "device") and obj.device:
        return getattr(obj.device, "tenant", None)
    if hasattr(obj, "virtual_machine") and obj.virtual_machine:
        return getattr(obj.virtual_machine, "tenant", None)
    return getattr(obj, "tenant", None)


class CertificateListView(generic.ObjectListView):
    """List all certificates."""

    queryset = Certificate.objects.defer(
        "pem_content", "issuer_chain", "chain_validation_message"
    ).prefetch_related("tenant", "assignments")
    filterset = CertificateFilterSet
    filterset_form = CertificateFilterForm
    table = CertificateTable


class CertificateView(generic.ObjectView):
    """Display a single certificate."""

    queryset = Certificate.objects.prefetch_related(
        "tenant",
        "assignments",
        "assignments__assigned_object_type",
    )

    def get_extra_context(self, request, instance):
        """Add assignments and lifecycle events to context."""
        assignments = instance.assignments.all()
        # Add lifecycle events for timeline tab
        lifecycle_events = instance.lifecycle_events.all()[:50]
        return {
            "assignments": assignments,
            "assignments_count": assignments.count(),
            "lifecycle_events": lifecycle_events,
        }


class CertificateEditView(generic.ObjectEditView):
    """Create or edit a certificate manually."""

    queryset = Certificate.objects.all()
    form = CertificateForm


class CertificateDeleteView(generic.ObjectDeleteView):
    """Delete a certificate."""

    queryset = Certificate.objects.all()


class CertificateBulkEditView(generic.BulkEditView):
    """Bulk edit certificates."""

    queryset = Certificate.objects.all()
    filterset = CertificateFilterSet
    table = CertificateTable
    form = CertificateBulkEditForm


class CertificateBulkDeleteView(generic.BulkDeleteView):
    """Bulk delete certificates."""

    queryset = Certificate.objects.all()
    filterset = CertificateFilterSet
    table = CertificateTable


class CertificateImportView(LoginRequiredMixin, View):
    """
    Smart Paste import view for PEM certificates.

    This view handles the import workflow:
    1. User pastes PEM content
    2. Certificate is parsed and validated
    3. Private keys are rejected
    4. Check for potential renewal (Janus workflow)
    5. Certificate is created
    """

    template_name = "netbox_ssl/certificate_import.html"

    def get(self, request):
        """Display the import form."""
        form = CertificateImportForm()

        # Check for renew_from query parameter (from detail page "Renew" button)
        renew_from = request.GET.get("renew_from")
        renew_certificate = None
        if renew_from:
            with contextlib.suppress(ValueError, TypeError, Certificate.DoesNotExist):
                renew_certificate = Certificate.objects.restrict(request.user, "view").get(pk=int(renew_from))

        return render(
            request,
            self.template_name,
            {
                "form": form,
                "renew_certificate": renew_certificate,
            },
        )

    def post(self, request):
        """Process the import form."""
        form = CertificateImportForm(request.POST)

        if not form.is_valid():
            return render(
                request,
                self.template_name,
                {
                    "form": form,
                },
            )

        pem_content = form.cleaned_data["pem_content"]
        private_key_location = form.cleaned_data.get("private_key_location", "")
        tenant = form.cleaned_data.get("tenant")

        try:
            # Parse the certificate
            parsed = CertificateParser.parse(pem_content)

            # Check for existing certificate (duplicate check)
            existing = (
                Certificate.objects.restrict(request.user, "view")
                .filter(
                    serial_number=parsed.serial_number,
                    issuer=parsed.issuer,
                )
                .first()
            )

            if existing:
                messages.error(
                    request,
                    _(f"Certificate already exists: {existing.common_name} (Serial: {existing.serial_number[:16]}...)"),
                )
                return render(
                    request,
                    self.template_name,
                    {
                        "form": form,
                    },
                )

            # Check for potential renewal candidate
            plugin_settings = settings.PLUGINS_CONFIG.get("netbox_ssl", {})
            warning_days = plugin_settings.get("expiry_warning_days", 30)
            renewal_candidate = CertificateParser.find_renewal_candidate(
                parsed.common_name,
                Certificate,
                warning_days=warning_days,
                tenant=tenant,
            )

            if renewal_candidate:
                # Store parsed data in session for renewal view
                request.session["pending_certificate"] = {
                    "common_name": parsed.common_name,
                    "serial_number": parsed.serial_number,
                    "fingerprint_sha256": parsed.fingerprint_sha256,
                    "issuer": parsed.issuer,
                    "valid_from": parsed.valid_from.isoformat(),
                    "valid_to": parsed.valid_to.isoformat(),
                    "sans": parsed.sans,
                    "key_size": parsed.key_size,
                    "algorithm": parsed.algorithm,
                    "pem_content": parsed.pem_content,
                    "issuer_chain": parsed.issuer_chain,
                    "private_key_location": private_key_location,
                    "tenant_id": tenant.pk if tenant else None,
                }
                request.session["renewal_candidate_id"] = renewal_candidate.pk

                return redirect(reverse("plugins:netbox_ssl:certificate_renew"))

            # Auto-detect issuing CA
            issuing_ca = detect_issuing_ca(parsed.issuer)

            # Create the certificate
            certificate = Certificate.objects.create(
                common_name=parsed.common_name,
                serial_number=parsed.serial_number,
                fingerprint_sha256=parsed.fingerprint_sha256,
                issuer=parsed.issuer,
                issuing_ca=issuing_ca,
                valid_from=parsed.valid_from,
                valid_to=parsed.valid_to,
                sans=parsed.sans,
                key_size=parsed.key_size,
                algorithm=parsed.algorithm,
                pem_content=parsed.pem_content,
                issuer_chain=parsed.issuer_chain,
                private_key_location=private_key_location,
                tenant=tenant,
                status=CertificateStatusChoices.STATUS_ACTIVE,
            )

            # Auto-detect ACME provider
            certificate.auto_detect_acme(save=True)

            # Show message with CA info if detected
            if issuing_ca:
                messages.success(
                    request,
                    _(f"Certificate imported successfully: {certificate.common_name} (CA: {issuing_ca.name})"),
                )
            else:
                messages.success(request, _(f"Certificate imported successfully: {certificate.common_name}"))
            return redirect(certificate.get_absolute_url())

        except PrivateKeyDetectedError as e:
            messages.error(request, str(e))
            return render(
                request,
                self.template_name,
                {
                    "form": form,
                },
            )
        except CertificateParseError as e:
            messages.error(request, str(e))
            return render(
                request,
                self.template_name,
                {
                    "form": form,
                },
            )


class CertificateRenewView(LoginRequiredMixin, View):
    """
    Janus Renewal workflow view.

    Handles the renewal prompt and atomic replacement:
    1. Shows comparison between old and new certificate
    2. On confirmation: creates new cert, copies assignments, archives old
    """

    template_name = "netbox_ssl/certificate_renew.html"

    def dispatch(self, request, *args, **kwargs):
        """Check permissions before dispatching."""
        if not request.user.has_perm("netbox_ssl.add_certificate") or not request.user.has_perm(
            "netbox_ssl.change_certificate"
        ):
            messages.error(request, _("You do not have permission to renew certificates."))
            return redirect(reverse("plugins:netbox_ssl:certificate_list"))
        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        """Display the renewal confirmation page."""
        pending_data = request.session.get("pending_certificate")
        renewal_candidate_id = request.session.get("renewal_candidate_id")

        if not pending_data or not renewal_candidate_id:
            messages.warning(request, _("No pending certificate renewal found."))
            return redirect(reverse("plugins:netbox_ssl:certificate_import"))

        old_certificate = get_object_or_404(
            Certificate.objects.restrict(request.user, "change"),
            pk=renewal_candidate_id,
        )

        # Parse ISO date strings into formatted dates for the template
        pending_data = dict(pending_data)
        pending_data["valid_from_formatted"] = datetime.fromisoformat(pending_data["valid_from"]).strftime(
            "%Y-%m-%d %H:%M"
        )
        pending_data["valid_to_formatted"] = datetime.fromisoformat(pending_data["valid_to"]).strftime("%Y-%m-%d %H:%M")

        # Get assignments for the old certificate
        assignments = old_certificate.assignments.select_related("assigned_object_type").all()

        return render(
            request,
            self.template_name,
            {
                "pending_certificate": pending_data,
                "old_certificate": old_certificate,
                "assignments": assignments,
            },
        )

    def post(self, request):
        """Process the renewal decision."""
        pending_data = request.session.get("pending_certificate")
        renewal_candidate_id = request.session.get("renewal_candidate_id")
        is_renewal = request.POST.get("is_renewal") == "yes"

        if not pending_data:
            messages.warning(request, _("No pending certificate data found."))
            return redirect(reverse("plugins:netbox_ssl:certificate_import"))

        # Get tenant if stored
        tenant = None
        if pending_data.get("tenant_id"):
            from tenancy.models import Tenant

            tenant = Tenant.objects.filter(pk=pending_data["tenant_id"]).first()

        # Parse dates back from ISO format
        valid_from = datetime.fromisoformat(pending_data["valid_from"])
        valid_to = datetime.fromisoformat(pending_data["valid_to"])

        # Auto-detect issuing CA
        issuing_ca = detect_issuing_ca(pending_data["issuer"])

        if is_renewal and renewal_candidate_id:
            # Janus Renewal: Replace & Archive
            old_certificate = get_object_or_404(
                Certificate.objects.restrict(request.user, "change"),
                pk=renewal_candidate_id,
            )

            # If the old certificate is tenant-scoped, carry it forward
            if tenant is None and old_certificate.tenant:
                tenant = old_certificate.tenant

            # Ensure assignments respect tenant boundaries
            if tenant:
                cross_tenant = []
                for assignment in old_certificate.assignments.all():
                    obj_tenant = _get_assigned_object_tenant(assignment.assigned_object)
                    if obj_tenant and obj_tenant != tenant:
                        cross_tenant.append(str(assignment.assigned_object))
                if cross_tenant:
                    messages.error(
                        request,
                        _(f"Renewal blocked due to cross-tenant assignments: {', '.join(cross_tenant[:5])}"),
                    )
                    return redirect(reverse("plugins:netbox_ssl:certificate_import"))

            with transaction.atomic():
                # Create new certificate
                new_certificate = Certificate.objects.create(
                    common_name=pending_data["common_name"],
                    serial_number=pending_data["serial_number"],
                    fingerprint_sha256=pending_data["fingerprint_sha256"],
                    issuer=pending_data["issuer"],
                    issuing_ca=issuing_ca,
                    valid_from=valid_from,
                    valid_to=valid_to,
                    sans=pending_data["sans"],
                    key_size=pending_data["key_size"],
                    algorithm=pending_data["algorithm"],
                    pem_content=pending_data["pem_content"],
                    issuer_chain=pending_data["issuer_chain"],
                    private_key_location=pending_data["private_key_location"],
                    tenant=tenant,
                    status=CertificateStatusChoices.STATUS_ACTIVE,
                )

                # Copy all assignments from old to new
                from ..models import CertificateAssignment

                for assignment in old_certificate.assignments.all():
                    new_assignment = CertificateAssignment(
                        certificate=new_certificate,
                        assigned_object_type=assignment.assigned_object_type,
                        assigned_object_id=assignment.assigned_object_id,
                        is_primary=assignment.is_primary,
                        notes=assignment.notes,
                    )
                    new_assignment.full_clean()
                    new_assignment.save()

                # Auto-detect ACME provider
                new_certificate.auto_detect_acme(save=True)

                # Archive old certificate
                old_certificate.status = CertificateStatusChoices.STATUS_REPLACED
                old_certificate.replaced_by = new_certificate
                old_certificate.save()

            # Fire renewal event for audit trail
            from ..utils.events import EVENT_CERTIFICATE_RENEWED, fire_certificate_event

            assignment_count = new_certificate.assignments.count()
            fire_certificate_event(
                new_certificate,
                EVENT_CERTIFICATE_RENEWED,
                extra={
                    "old_certificate_id": old_certificate.pk,
                    "old_certificate_cn": old_certificate.common_name,
                    "assignments_transferred": assignment_count,
                },
            )

            # Clear session data
            del request.session["pending_certificate"]
            del request.session["renewal_candidate_id"]

            messages.success(
                request,
                _(
                    f"Certificate renewed successfully. {assignment_count} "
                    f"assignment(s) transferred. Old certificate archived."
                ),
            )
            return redirect(new_certificate.get_absolute_url())

        else:
            # Not a renewal, just create as new
            certificate = Certificate.objects.create(
                common_name=pending_data["common_name"],
                serial_number=pending_data["serial_number"],
                fingerprint_sha256=pending_data["fingerprint_sha256"],
                issuer=pending_data["issuer"],
                issuing_ca=issuing_ca,
                valid_from=valid_from,
                valid_to=valid_to,
                sans=pending_data["sans"],
                key_size=pending_data["key_size"],
                algorithm=pending_data["algorithm"],
                pem_content=pending_data["pem_content"],
                issuer_chain=pending_data["issuer_chain"],
                private_key_location=pending_data["private_key_location"],
                tenant=tenant,
                status=CertificateStatusChoices.STATUS_ACTIVE,
            )

            # Clear session data
            del request.session["pending_certificate"]
            if "renewal_candidate_id" in request.session:
                del request.session["renewal_candidate_id"]

            messages.success(request, _(f"Certificate imported successfully: {certificate.common_name}"))
            return redirect(certificate.get_absolute_url())


class CertificateBulkDataImportView(LoginRequiredMixin, View):
    """
    Bulk import certificates from CSV or JSON data.

    Two-step flow:
    1. POST data -> parse and validate -> show preview
    2. Confirm -> create certificates
    """

    template_name = "netbox_ssl/certificate_bulk_import.html"
    MAX_UPLOAD_SIZE = 5 * 1024 * 1024  # 5 MB
    MAX_SESSION_ROWS = 500

    def dispatch(self, request, *args, **kwargs):
        """Check permissions before dispatching."""
        if not request.user.has_perm("netbox_ssl.add_certificate"):
            messages.error(request, _("You do not have permission to import certificates."))
            return redirect(reverse("plugins:netbox_ssl:certificate_list"))
        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        """Display the bulk import form."""
        return render(request, self.template_name, {"step": "input"})

    def post(self, request):
        """Handle form submission for parse/preview or confirm."""
        # Confirm step
        if request.POST.get("confirm") == "yes":
            return self._confirm_import(request)

        # Parse step
        content = ""
        import_format = request.POST.get("import_format", "auto")

        # Handle file upload or pasted content
        if request.FILES.get("data_file"):
            uploaded = request.FILES["data_file"]
            if uploaded.size > self.MAX_UPLOAD_SIZE:
                messages.error(request, _(f"File too large ({uploaded.size // 1024} KB). Maximum is 5 MB."))
                return render(request, self.template_name, {"step": "input"})
            content = uploaded.read().decode("utf-8-sig")
        else:
            content = request.POST.get("data_content", "")

        if len(content) > self.MAX_UPLOAD_SIZE:
            messages.error(request, _("Pasted content too large."))
            return render(request, self.template_name, {"step": "input"})

        if not content.strip():
            messages.error(request, _("No data provided. Paste CSV/JSON or upload a file."))
            return render(request, self.template_name, {"step": "input"})

        result = bulk_parse(content, fmt=import_format)

        if result.has_errors and not result.valid_rows:
            return render(
                request,
                self.template_name,
                {
                    "step": "input",
                    "errors": result.errors,
                    "data_content": content,
                },
            )

        # Check for duplicates against existing certificates
        duplicates = []
        new_rows = []
        for row in result.valid_rows:
            exists = Certificate.objects.filter(
                serial_number=row["serial_number"],
                issuer=row["issuer"],
            ).exists()
            if exists:
                duplicates.append(row["common_name"])
            else:
                new_rows.append(row)

        # Enforce session storage limit
        if len(new_rows) > self.MAX_SESSION_ROWS:
            messages.warning(
                request,
                _(
                    f"Too many rows ({len(new_rows)}). Maximum is {self.MAX_SESSION_ROWS}. Please split into smaller batches."
                ),
            )
            new_rows = new_rows[: self.MAX_SESSION_ROWS]

        # Store validated data in session for confirm step
        serializable_rows = []
        for row in new_rows:
            sr = dict(row)
            sr["valid_from"] = sr["valid_from"].isoformat()
            sr["valid_to"] = sr["valid_to"].isoformat()
            serializable_rows.append(sr)
        request.session["bulk_import_rows"] = serializable_rows

        return render(
            request,
            self.template_name,
            {
                "step": "preview",
                "rows": new_rows,
                "errors": result.errors,
                "duplicates": duplicates,
                "total_parsed": len(result.valid_rows),
                "new_count": len(new_rows),
            },
        )

    def _confirm_import(self, request):
        """Create certificates from session data."""
        from tenancy.models import Tenant

        rows = request.session.pop("bulk_import_rows", [])
        if not rows:
            messages.warning(request, _("No pending import data found."))
            return redirect(reverse("plugins:netbox_ssl:certificate_bulk_import"))

        # Build set of tenants this user can access
        user_tenants = Tenant.objects.restrict(request.user, "view")

        created = 0
        errors = []

        with transaction.atomic():
            for idx, row in enumerate(rows, start=1):
                try:
                    # Resolve tenant (restricted to user's accessible tenants)
                    tenant = None
                    tenant_ref = row.pop("tenant_ref", None)
                    if tenant_ref:
                        try:
                            tenant = user_tenants.get(pk=int(tenant_ref))
                        except (ValueError, Tenant.DoesNotExist):
                            tenant = user_tenants.filter(name=tenant_ref).first()

                    # Parse dates back
                    valid_from = datetime.fromisoformat(row["valid_from"])
                    valid_to = datetime.fromisoformat(row["valid_to"])

                    issuing_ca = detect_issuing_ca(row["issuer"])

                    cert = Certificate.objects.create(
                        common_name=row["common_name"],
                        serial_number=row["serial_number"],
                        fingerprint_sha256=row["fingerprint_sha256"],
                        issuer=row["issuer"],
                        issuing_ca=issuing_ca,
                        valid_from=valid_from,
                        valid_to=valid_to,
                        sans=row.get("sans", []),
                        key_size=row.get("key_size"),
                        algorithm=row.get("algorithm", "unknown"),
                        status=row.get("status", CertificateStatusChoices.STATUS_ACTIVE),
                        private_key_location=row.get("private_key_location", ""),
                        pem_content=row.get("pem_content", ""),
                        issuer_chain=row.get("issuer_chain", ""),
                        tenant=tenant,
                    )
                    cert.auto_detect_acme(save=True)
                    created += 1
                except Exception as e:
                    errors.append(f"Row {idx}: {e}")

        if created:
            messages.success(request, _(f"Successfully imported {created} certificate(s)."))
        if errors:
            for err in errors[:5]:
                messages.error(request, err)

        return redirect(reverse("plugins:netbox_ssl:certificate_list"))
