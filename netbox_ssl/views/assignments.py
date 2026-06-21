"""
Views for CertificateAssignment model.
"""

from dcim.models import Device
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.contenttypes.models import ContentType
from django.shortcuts import get_object_or_404, redirect, render
from django.views import View
from ipam.models import Service
from netbox.views import generic
from virtualization.models import VirtualMachine

from ..filtersets import CertificateAssignmentFilterSet
from ..forms import CertificateAssignmentFilterForm, CertificateAssignmentForm, CertificateBulkAssignForm
from ..models import Certificate, CertificateAssignment
from ..tables import CertificateAssignmentTable
from ..utils.assignments import AssignmentError, assign_certificate_to_targets


class CertificateAssignmentListView(generic.ObjectListView):
    """List all certificate assignments."""

    queryset = CertificateAssignment.objects.prefetch_related(
        "certificate",
        "assigned_object_type",
    )
    filterset = CertificateAssignmentFilterSet
    filterset_form = CertificateAssignmentFilterForm
    table = CertificateAssignmentTable


class CertificateAssignmentView(generic.ObjectView):
    """Display a single certificate assignment."""

    queryset = CertificateAssignment.objects.prefetch_related(
        "certificate",
        "assigned_object_type",
    )


class CertificateAssignmentEditView(generic.ObjectEditView):
    """Create or edit a certificate assignment."""

    queryset = CertificateAssignment.objects.all()
    form = CertificateAssignmentForm


class CertificateAssignmentDeleteView(generic.ObjectDeleteView):
    """Delete a certificate assignment."""

    queryset = CertificateAssignment.objects.all()


class CertificateAssignmentBulkDeleteView(generic.BulkDeleteView):
    """Bulk delete certificate assignments."""

    queryset = CertificateAssignment.objects.all()
    filterset = CertificateAssignmentFilterSet
    table = CertificateAssignmentTable


class CertificateAssignTargetsView(LoginRequiredMixin, View):
    """Assign one certificate to many Devices/VMs/Services from its detail page."""

    template_name = "netbox_ssl/certificate_assign_targets.html"

    def _get_certificate(self, request, pk: int) -> Certificate:
        return get_object_or_404(Certificate.objects.restrict(request.user, "view"), pk=pk)

    def get(self, request, pk: int):
        certificate = self._get_certificate(request, pk)
        return render(
            request,
            self.template_name,
            {"object": certificate, "form": CertificateBulkAssignForm()},
        )

    def post(self, request, pk: int):
        certificate = self._get_certificate(request, pk)
        if not request.user.has_perm("netbox_ssl.add_certificateassignment"):
            messages.error(request, "You do not have permission to assign certificates.")
            return redirect(certificate.get_absolute_url())

        form = CertificateBulkAssignForm(request.POST)
        if not form.is_valid():
            return render(
                request,
                self.template_name,
                {"object": certificate, "form": form},
            )

        targets: list[tuple[ContentType, int]] = []
        for device in form.cleaned_data["devices"]:
            targets.append((ContentType.objects.get_for_model(Device), device.pk))
        for vm in form.cleaned_data["virtual_machines"]:
            targets.append((ContentType.objects.get_for_model(VirtualMachine), vm.pk))
        for service in form.cleaned_data["services"]:
            targets.append((ContentType.objects.get_for_model(Service), service.pk))

        try:
            result = assign_certificate_to_targets(certificate, targets, is_primary=form.cleaned_data["is_primary"])
        except AssignmentError as exc:
            messages.error(request, str(exc))
            return redirect(certificate.get_absolute_url())

        messages.success(
            request,
            f"Assigned {result.created}, skipped {result.skipped} already assigned.",
        )
        return redirect(certificate.get_absolute_url())
