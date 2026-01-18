"""
NetBox SSL Plugin - Project Janus

A NetBox plugin for TLS/SSL certificate management.
Provides a "Single Source of Truth" for certificate inventory and lifecycle management.
"""

from netbox.plugins import PluginConfig

__version__ = "0.1.0"


class NetBoxSSLConfig(PluginConfig):
    """NetBox SSL Plugin configuration."""

    name = "netbox_ssl"
    verbose_name = "NetBox SSL"
    description = "TLS/SSL Certificate Management for NetBox"
    version = __version__
    author = "NetBox SSL Team"
    author_email = "info@example.com"
    base_url = "ssl"
    min_version = "4.4.0"
    max_version = "4.5.99"
    required_settings = []
    default_settings = {
        "expiry_warning_days": 30,
        "expiry_critical_days": 14,
    }

    def ready(self):
        """Called when the plugin is ready. Register system checks, widgets, and template extensions."""
        super().ready()
        # Import checks to register them with Django's check framework
        # Import dashboard widgets (registers via @register_widget decorator)
        from . import (
            checks,  # noqa: F401
            dashboard,  # noqa: F401
        )

        # Import template extensions
        from .template_content import template_extensions  # noqa: F401


config = NetBoxSSLConfig
