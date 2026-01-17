"""
REST API URL configuration for NetBox SSL plugin.
"""

from netbox.api.routers import NetBoxRouter

from . import views

router = NetBoxRouter()
router.register("certificates", views.CertificateViewSet)
router.register("assignments", views.CertificateAssignmentViewSet)

urlpatterns = router.urls
