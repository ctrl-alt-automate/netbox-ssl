"""
Email notification utility for certificate expiry alerts.

Sends HTML and plain-text emails using Django's mail framework.
Requires Django EMAIL_* settings to be configured on the NetBox server.
"""

import logging

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string

logger = logging.getLogger("netbox_ssl.email")


def _get_plugin_setting(name: str, default=None):
    """Get a plugin setting from PLUGINS_CONFIG."""
    return settings.PLUGINS_CONFIG.get("netbox_ssl", {}).get(name, default)


def send_expiry_report(
    report_data: dict,
    recipients: list[str] | None = None,
    base_url: str = "",
) -> bool:
    """
    Send a certificate expiry report via email.

    Args:
        report_data: Report dict with 'expired', 'critical', 'warning' keys
                     (as returned by CertificateExpiryNotification.run())
        recipients: List of email addresses. Falls back to plugin setting.
        base_url: Base URL for certificate links (e.g. "https://netbox.example.com")

    Returns:
        True if email was sent successfully, False otherwise.
    """
    if not _get_plugin_setting("notification_email_enabled", False):
        logger.info("Email notifications disabled in plugin settings")
        return False

    if not recipients:
        recipients = _get_plugin_setting("notification_email_recipients", [])

    if not recipients:
        logger.warning("No email recipients configured")
        return False

    summary = report_data.get("summary", {})
    total = summary.get("total_alerts", 0)

    if total == 0:
        logger.info("No alerts to send — skipping email")
        return False

    prefix = _get_plugin_setting("notification_email_subject_prefix", "[NetBox SSL]")
    subject = f"{prefix} {total} certificate(s) require attention"

    context = {
        "report": report_data,
        "summary": summary,
        "base_url": base_url.rstrip("/"),
    }

    text_body = render_to_string("netbox_ssl/email/expiry_report.txt", context)
    html_body = render_to_string("netbox_ssl/email/expiry_report.html", context)

    from_email = settings.DEFAULT_FROM_EMAIL

    try:
        msg = EmailMultiAlternatives(subject, text_body, from_email, recipients)
        msg.attach_alternative(html_body, "text/html")
        msg.send()
        logger.info("Expiry report sent to %d recipient(s)", len(recipients))
        return True
    except Exception:
        logger.exception("Failed to send expiry report email")
        return False
