"""
Views for CertificateSigningRequest model.
"""

from django.contrib import messages
from django.shortcuts import redirect, render
from django.utils.translation import gettext_lazy as _
from django.views.generic import View
from netbox.views import generic

from ..filtersets import CertificateSigningRequestFilterSet
from ..forms import (
    CertificateSigningRequestBulkEditForm,
    CertificateSigningRequestFilterForm,
    CertificateSigningRequestForm,
    CSRImportForm,
)
from ..models import CertificateSigningRequest, CSRStatusChoices
from ..tables import CertificateSigningRequestTable
from ..utils import CSRParseError, CSRParser


class CertificateSigningRequestListView(generic.ObjectListView):
    """List all CSRs."""

    queryset = CertificateSigningRequest.objects.prefetch_related(
        "tenant",
        "resulting_certificate",
    )
    filterset = CertificateSigningRequestFilterSet
    filterset_form = CertificateSigningRequestFilterForm
    table = CertificateSigningRequestTable


class CertificateSigningRequestView(generic.ObjectView):
    """Display a single CSR."""

    queryset = CertificateSigningRequest.objects.prefetch_related(
        "tenant",
        "resulting_certificate",
    )


class CertificateSigningRequestEditView(generic.ObjectEditView):
    """Create or edit a CSR manually."""

    queryset = CertificateSigningRequest.objects.all()
    form = CertificateSigningRequestForm


class CertificateSigningRequestDeleteView(generic.ObjectDeleteView):
    """Delete a CSR."""

    queryset = CertificateSigningRequest.objects.all()


class CertificateSigningRequestBulkEditView(generic.BulkEditView):
    """Bulk edit CSRs."""

    queryset = CertificateSigningRequest.objects.all()
    filterset = CertificateSigningRequestFilterSet
    table = CertificateSigningRequestTable
    form = CertificateSigningRequestBulkEditForm


class CertificateSigningRequestBulkDeleteView(generic.BulkDeleteView):
    """Bulk delete CSRs."""

    queryset = CertificateSigningRequest.objects.all()
    filterset = CertificateSigningRequestFilterSet
    table = CertificateSigningRequestTable


class CSRImportView(View):
    """
    Import view for PEM CSRs.

    This view handles the CSR import workflow:
    1. User pastes PEM content
    2. CSR is parsed and validated
    3. CSR record is created
    """

    template_name = "netbox_ssl/csr_import.html"

    def get(self, request):
        """Display the import form."""
        form = CSRImportForm()
        return render(
            request,
            self.template_name,
            {
                "form": form,
            },
        )

    def post(self, request):
        """Process the import form."""
        form = CSRImportForm(request.POST)

        if not form.is_valid():
            return render(
                request,
                self.template_name,
                {
                    "form": form,
                },
            )

        pem_content = form.cleaned_data["pem_content"]
        requested_by = form.cleaned_data.get("requested_by", "")
        target_ca = form.cleaned_data.get("target_ca", "")
        tenant = form.cleaned_data.get("tenant")

        try:
            # Parse the CSR
            parsed = CSRParser.parse(pem_content)

            # Check for existing CSR (duplicate check)
            existing = CertificateSigningRequest.objects.filter(
                fingerprint_sha256=parsed.fingerprint_sha256,
            ).first()

            if existing:
                messages.error(
                    request,
                    _(f"CSR already exists: {existing.common_name}"),
                )
                return render(
                    request,
                    self.template_name,
                    {
                        "form": form,
                    },
                )

            # Create the CSR
            csr = CertificateSigningRequest.objects.create(
                common_name=parsed.common_name,
                organization=parsed.organization,
                organizational_unit=parsed.organizational_unit,
                locality=parsed.locality,
                state=parsed.state,
                country=parsed.country,
                sans=parsed.sans,
                key_size=parsed.key_size,
                algorithm=parsed.algorithm,
                fingerprint_sha256=parsed.fingerprint_sha256,
                pem_content=parsed.pem_content,
                requested_by=requested_by,
                target_ca=target_ca,
                tenant=tenant,
                status=CSRStatusChoices.STATUS_PENDING,
            )

            messages.success(request, _(f"CSR imported successfully: {csr.common_name}"))
            return redirect(csr.get_absolute_url())

        except CSRParseError as e:
            messages.error(request, str(e))
            return render(
                request,
                self.template_name,
                {
                    "form": form,
                },
            )
