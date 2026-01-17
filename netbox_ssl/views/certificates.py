"""
Views for Certificate model.

Includes Smart Paste import and Janus Renewal workflow views.
"""

from django.contrib import messages
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from django.views.generic import View

from netbox.views import generic

from ..filtersets import CertificateFilterSet
from ..forms import (
    CertificateForm,
    CertificateFilterForm,
    CertificateBulkEditForm,
    CertificateImportForm,
)
from ..models import Certificate, CertificateStatusChoices
from ..tables import CertificateTable
from ..utils import CertificateParser, CertificateParseError, PrivateKeyDetectedError


class CertificateListView(generic.ObjectListView):
    """List all certificates."""

    queryset = Certificate.objects.prefetch_related("tenant", "assignments")
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
        """Add assignments to context."""
        assignments = instance.assignments.all()
        return {
            "assignments": assignments,
            "assignments_count": assignments.count(),
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


class CertificateImportView(View):
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
        return render(request, self.template_name, {
            "form": form,
        })

    def post(self, request):
        """Process the import form."""
        form = CertificateImportForm(request.POST)

        if not form.is_valid():
            return render(request, self.template_name, {
                "form": form,
            })

        pem_content = form.cleaned_data["pem_content"]
        private_key_location = form.cleaned_data.get("private_key_location", "")
        tenant = form.cleaned_data.get("tenant")

        try:
            # Parse the certificate
            parsed = CertificateParser.parse(pem_content)

            # Check for existing certificate (duplicate check)
            existing = Certificate.objects.filter(
                serial_number=parsed.serial_number,
                issuer=parsed.issuer,
            ).first()

            if existing:
                messages.error(
                    request,
                    _(f"Certificate already exists: {existing.common_name} "
                      f"(Serial: {existing.serial_number[:16]}...)")
                )
                return render(request, self.template_name, {
                    "form": form,
                })

            # Check for potential renewal candidate
            renewal_candidate = CertificateParser.find_renewal_candidate(
                parsed.common_name,
                Certificate,
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

                return redirect(
                    reverse("plugins:netbox_ssl:certificate_renew")
                )

            # Create the certificate
            certificate = Certificate.objects.create(
                common_name=parsed.common_name,
                serial_number=parsed.serial_number,
                fingerprint_sha256=parsed.fingerprint_sha256,
                issuer=parsed.issuer,
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

            messages.success(
                request,
                _(f"Certificate imported successfully: {certificate.common_name}")
            )
            return redirect(certificate.get_absolute_url())

        except PrivateKeyDetectedError as e:
            messages.error(request, str(e))
            return render(request, self.template_name, {
                "form": form,
            })
        except CertificateParseError as e:
            messages.error(request, str(e))
            return render(request, self.template_name, {
                "form": form,
            })


class CertificateRenewView(View):
    """
    Janus Renewal workflow view.

    Handles the renewal prompt and atomic replacement:
    1. Shows comparison between old and new certificate
    2. On confirmation: creates new cert, copies assignments, archives old
    """

    template_name = "netbox_ssl/certificate_renew.html"

    def get(self, request):
        """Display the renewal confirmation page."""
        pending_data = request.session.get("pending_certificate")
        renewal_candidate_id = request.session.get("renewal_candidate_id")

        if not pending_data or not renewal_candidate_id:
            messages.warning(request, _("No pending certificate renewal found."))
            return redirect(reverse("plugins:netbox_ssl:certificate_import"))

        old_certificate = get_object_or_404(Certificate, pk=renewal_candidate_id)

        return render(request, self.template_name, {
            "pending_certificate": pending_data,
            "old_certificate": old_certificate,
        })

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
        from datetime import datetime
        valid_from = datetime.fromisoformat(pending_data["valid_from"])
        valid_to = datetime.fromisoformat(pending_data["valid_to"])

        if is_renewal and renewal_candidate_id:
            # Janus Renewal: Replace & Archive
            old_certificate = get_object_or_404(Certificate, pk=renewal_candidate_id)

            with transaction.atomic():
                # Create new certificate
                new_certificate = Certificate.objects.create(
                    common_name=pending_data["common_name"],
                    serial_number=pending_data["serial_number"],
                    fingerprint_sha256=pending_data["fingerprint_sha256"],
                    issuer=pending_data["issuer"],
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
                    CertificateAssignment.objects.create(
                        certificate=new_certificate,
                        assigned_object_type=assignment.assigned_object_type,
                        assigned_object_id=assignment.assigned_object_id,
                        is_primary=assignment.is_primary,
                        notes=assignment.notes,
                    )

                # Archive old certificate
                old_certificate.status = CertificateStatusChoices.STATUS_REPLACED
                old_certificate.replaced_by = new_certificate
                old_certificate.save()

            # Clear session data
            del request.session["pending_certificate"]
            del request.session["renewal_candidate_id"]

            messages.success(
                request,
                _(f"Certificate renewed successfully. {old_certificate.assignments.count()} "
                  f"assignment(s) transferred. Old certificate archived.")
            )
            return redirect(new_certificate.get_absolute_url())

        else:
            # Not a renewal, just create as new
            certificate = Certificate.objects.create(
                common_name=pending_data["common_name"],
                serial_number=pending_data["serial_number"],
                fingerprint_sha256=pending_data["fingerprint_sha256"],
                issuer=pending_data["issuer"],
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

            messages.success(
                request,
                _(f"Certificate imported successfully: {certificate.common_name}")
            )
            return redirect(certificate.get_absolute_url())
