"""
REST API URL configuration for NetBox SSL plugin.
"""

from netbox.api.routers import NetBoxRouter

from . import views

router = NetBoxRouter()
router.register("certificates", views.CertificateViewSet)
router.register("assignments", views.CertificateAssignmentViewSet)
router.register("certificate-authorities", views.CertificateAuthorityViewSet)
router.register("csrs", views.CertificateSigningRequestViewSet)

urlpatterns = router.urls
