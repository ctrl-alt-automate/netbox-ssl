"""
NetBox SSL custom scripts.
"""

from .expiry_notification import CertificateExpiryNotification

__all__ = ["CertificateExpiryNotification"]
