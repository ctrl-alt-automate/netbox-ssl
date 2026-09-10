"""
NetBox SSL custom scripts.

Every ``Script`` subclass bundled with the plugin must be re-exported here.
NetBox does not auto-discover plugin-bundled scripts: users register them with
a wrapper module in ``SCRIPTS_ROOT`` that imports from this package (see
``docs/reference/scripts.md``). A script missing from ``__all__`` is therefore
unreachable -- see issue #163. ``tests/test_script_exports.py`` guards this.
"""

from .ari_poll import CertificateARIPoll
from .auto_archive import CertificateAutoArchive
from .compliance_check import CertificateComplianceCheck
from .endpoint_monitor import MonitoredEndpointPoll
from .expiry_notification import CertificateExpiryNotification
from .expiry_scan import CertificateExpiryScan
from .external_sync import ExternalSourceSync
from .scheduled_export import ScheduledCertificateExport
from .url_scan import CertificateURLScan

__all__ = [
    "CertificateARIPoll",
    "CertificateAutoArchive",
    "CertificateComplianceCheck",
    "CertificateExpiryNotification",
    "CertificateExpiryScan",
    "CertificateURLScan",
    "ExternalSourceSync",
    "MonitoredEndpointPoll",
    "ScheduledCertificateExport",
]
