from .certificates import (
    CertificateListView,
    CertificateView,
    CertificateEditView,
    CertificateDeleteView,
    CertificateBulkEditView,
    CertificateBulkDeleteView,
    CertificateImportView,
    CertificateRenewView,
)
from .assignments import (
    CertificateAssignmentListView,
    CertificateAssignmentView,
    CertificateAssignmentEditView,
    CertificateAssignmentDeleteView,
    CertificateAssignmentBulkDeleteView,
)

__all__ = [
    # Certificate views
    "CertificateListView",
    "CertificateView",
    "CertificateEditView",
    "CertificateDeleteView",
    "CertificateBulkEditView",
    "CertificateBulkDeleteView",
    "CertificateImportView",
    "CertificateRenewView",
    # Assignment views
    "CertificateAssignmentListView",
    "CertificateAssignmentView",
    "CertificateAssignmentEditView",
    "CertificateAssignmentDeleteView",
    "CertificateAssignmentBulkDeleteView",
]
