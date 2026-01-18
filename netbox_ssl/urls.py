"""
URL configuration for NetBox SSL plugin.
"""

from django.urls import path
from netbox.views.generic import ObjectChangeLogView

from . import models, views

urlpatterns = [
    # Certificate URLs
    path(
        "certificates/",
        views.CertificateListView.as_view(),
        name="certificate_list",
    ),
    path(
        "certificates/add/",
        views.CertificateEditView.as_view(),
        name="certificate_add",
    ),
    path(
        "certificates/import/",
        views.CertificateImportView.as_view(),
        name="certificate_import",
    ),
    path(
        "certificates/renew/",
        views.CertificateRenewView.as_view(),
        name="certificate_renew",
    ),
    path(
        "certificates/edit/",
        views.CertificateBulkEditView.as_view(),
        name="certificate_bulk_edit",
    ),
    path(
        "certificates/delete/",
        views.CertificateBulkDeleteView.as_view(),
        name="certificate_bulk_delete",
    ),
    path(
        "certificates/<int:pk>/",
        views.CertificateView.as_view(),
        name="certificate",
    ),
    path(
        "certificates/<int:pk>/edit/",
        views.CertificateEditView.as_view(),
        name="certificate_edit",
    ),
    path(
        "certificates/<int:pk>/delete/",
        views.CertificateDeleteView.as_view(),
        name="certificate_delete",
    ),
    path(
        "certificates/<int:pk>/changelog/",
        ObjectChangeLogView.as_view(),
        name="certificate_changelog",
        kwargs={"model": models.Certificate},
    ),
    # CertificateAssignment URLs
    path(
        "assignments/",
        views.CertificateAssignmentListView.as_view(),
        name="certificateassignment_list",
    ),
    path(
        "assignments/add/",
        views.CertificateAssignmentEditView.as_view(),
        name="certificateassignment_add",
    ),
    path(
        "assignments/delete/",
        views.CertificateAssignmentBulkDeleteView.as_view(),
        name="certificateassignment_bulk_delete",
    ),
    path(
        "assignments/<int:pk>/",
        views.CertificateAssignmentView.as_view(),
        name="certificateassignment",
    ),
    path(
        "assignments/<int:pk>/edit/",
        views.CertificateAssignmentEditView.as_view(),
        name="certificateassignment_edit",
    ),
    path(
        "assignments/<int:pk>/delete/",
        views.CertificateAssignmentDeleteView.as_view(),
        name="certificateassignment_delete",
    ),
    path(
        "assignments/<int:pk>/changelog/",
        ObjectChangeLogView.as_view(),
        name="certificateassignment_changelog",
        kwargs={"model": models.CertificateAssignment},
    ),
]
