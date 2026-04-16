"""
Django system checks for NetBox SSL plugin.

These checks validate the plugin configuration and environment.
Run with: python manage.py check --tag netbox_ssl

Or as part of all checks: python manage.py check
"""

from django.core.checks import Error, Info, Tags, Warning, register


@register(Tags.models)
def check_certificate_model(app_configs, **kwargs):
    """Check that the Certificate model is properly configured."""
    errors = []

    try:
        from netbox_ssl.models import Certificate

        # Check that all required fields exist
        required_fields = [
            "common_name",
            "serial_number",
            "fingerprint_sha256",
            "issuer",
            "valid_from",
            "valid_to",
            "algorithm",
            "status",
        ]

        for field_name in required_fields:
            if not hasattr(Certificate, field_name):
                errors.append(
                    Error(
                        f"Certificate model is missing required field: {field_name}",
                        hint=f"Add the {field_name} field to the Certificate model.",
                        obj=Certificate,
                        id="netbox_ssl.E001",
                    )
                )

        # Check that required methods exist
        required_methods = [
            "days_remaining",
            "is_expired",
            "get_absolute_url",
        ]

        for method_name in required_methods:
            if not hasattr(Certificate, method_name):
                errors.append(
                    Error(
                        f"Certificate model is missing required method/property: {method_name}",
                        hint=f"Add the {method_name} property/method to the Certificate model.",
                        obj=Certificate,
                        id="netbox_ssl.E002",
                    )
                )

    except ImportError as e:
        errors.append(
            Error(
                "Cannot import Certificate model",
                hint=f"Ensure netbox_ssl.models.Certificate exists and is properly defined. Error: {e}",
                id="netbox_ssl.E003",
            )
        )

    return errors


@register(Tags.models)
def check_assignment_model(app_configs, **kwargs):
    """Check that the CertificateAssignment model is properly configured."""
    errors = []

    try:
        from netbox_ssl.models import CertificateAssignment

        # Check for GenericForeignKey support
        required_fields = [
            "certificate",
            "assigned_object_type",
            "assigned_object_id",
        ]

        for field_name in required_fields:
            if not hasattr(CertificateAssignment, field_name):
                errors.append(
                    Error(
                        f"CertificateAssignment model is missing required field: {field_name}",
                        hint=f"Add the {field_name} field to the CertificateAssignment model.",
                        obj=CertificateAssignment,
                        id="netbox_ssl.E004",
                    )
                )

    except ImportError as e:
        errors.append(
            Error(
                "Cannot import CertificateAssignment model",
                hint=f"Ensure netbox_ssl.models.CertificateAssignment exists. Error: {e}",
                id="netbox_ssl.E005",
            )
        )

    return errors


@register(Tags.urls)
def check_url_configuration(app_configs, **kwargs):
    """Check that all required URLs are registered."""
    errors = []

    try:
        from django.urls import NoReverseMatch, reverse

        # Check plugin URLs
        required_urls = [
            ("plugins:netbox_ssl:certificate_list", "Certificate list"),
            ("plugins:netbox_ssl:certificate_add", "Certificate add"),
            ("plugins:netbox_ssl:certificate_import", "Certificate import"),
            ("plugins:netbox_ssl:certificateassignment_list", "Assignment list"),
        ]

        for url_name, description in required_urls:
            try:
                reverse(url_name)
            except NoReverseMatch:
                errors.append(
                    Error(
                        f"URL pattern not found: {url_name}",
                        hint=f"Ensure the {description} URL is registered in urls.py",
                        id="netbox_ssl.E006",
                    )
                )

    except Exception as e:
        errors.append(
            Warning(
                f"Could not verify URL configuration: {e}",
                hint="This may indicate a problem with the URL configuration.",
                id="netbox_ssl.W001",
            )
        )

    return errors


@register(Tags.templates)
def check_templates(app_configs, **kwargs):
    """Check that required templates exist."""
    errors = []

    try:
        from django.template import TemplateDoesNotExist
        from django.template.loader import get_template

        required_templates = [
            "netbox_ssl/certificate.html",
            "netbox_ssl/certificate_list.html",
            "netbox_ssl/certificate_import.html",
            "netbox_ssl/certificateassignment.html",
            "netbox_ssl/certificateassignment_list.html",
        ]

        for template_name in required_templates:
            try:
                get_template(template_name)
            except TemplateDoesNotExist:
                errors.append(
                    Warning(
                        f"Required template not found: {template_name}",
                        hint=f"Ensure the plugin is installed with package data intact. "
                        f"Expected template at templates/{template_name}",
                        id="netbox_ssl.W010",
                    )
                )

    except Exception as e:
        errors.append(
            Warning(
                f"Could not verify templates: {e}",
                hint="This may indicate a template configuration issue.",
                id="netbox_ssl.W002",
            )
        )

    return errors


@register(Tags.security)
def check_security_configuration(app_configs, **kwargs):
    """Check security-related configuration."""
    warnings = []

    try:
        from netbox_ssl.utils.parser import CertificateParser

        # Verify private key detection works
        test_key = "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"
        if not CertificateParser.contains_private_key(test_key):
            warnings.append(
                Warning(
                    "Private key detection may not be working correctly",
                    hint="The CertificateParser.contains_private_key() method should detect private keys.",
                    id="netbox_ssl.W003",
                )
            )

    except Exception as e:
        warnings.append(
            Warning(
                f"Could not verify security configuration: {e}",
                hint="Ensure the certificate parser is properly configured.",
                id="netbox_ssl.W004",
            )
        )

    return warnings


@register()
def check_dependencies(app_configs, **kwargs):
    """Check that required dependencies are installed."""
    errors = []

    # Check cryptography library
    try:
        import cryptography  # noqa: F401
        from cryptography import x509  # noqa: F401
    except ImportError:
        errors.append(
            Error(
                "Required dependency 'cryptography' is not installed",
                hint="Install cryptography: pip install cryptography",
                id="netbox_ssl.E008",
            )
        )

    # Check that we can parse certificates
    try:
        from cryptography.hazmat.primitives import hashes  # noqa: F401
        from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: F401
    except ImportError as e:
        errors.append(
            Error(
                f"Cryptography library components not available: {e}",
                hint="Reinstall cryptography with: pip install --force-reinstall cryptography",
                id="netbox_ssl.E009",
            )
        )

    return errors


@register(Tags.database)
def check_database_tables(app_configs, **kwargs):
    """Check that database tables are properly created."""
    warnings = []

    try:
        from django.db import connection

        # Check if tables exist
        tables = connection.introspection.table_names()

        expected_tables = [
            "netbox_ssl_certificate",
            "netbox_ssl_certificateassignment",
        ]

        missing_tables = [t for t in expected_tables if t not in tables]

        if len(missing_tables) == len(expected_tables):
            # All tables missing — fresh install, not yet migrated
            warnings.append(
                Info(
                    "Plugin tables not yet created. Run: python manage.py migrate netbox_ssl",
                    hint="This is expected on a fresh install before running migrations.",
                    id="netbox_ssl.I002",
                )
            )
        else:
            # Partial — some tables exist, some don't
            for table in missing_tables:
                warnings.append(
                    Warning(
                        f"Database table not found: {table}",
                        hint="Run migrations: python manage.py migrate netbox_ssl",
                        id="netbox_ssl.W005",
                    )
                )

    except Exception as e:
        warnings.append(
            Warning(
                f"Could not verify database tables: {e}",
                hint="Ensure database connectivity and run migrations.",
                id="netbox_ssl.W006",
            )
        )

    return warnings


# Custom check tags
class NetBoxSSLTags:
    """Custom check tags for the plugin."""

    netbox_ssl = "netbox_ssl"


@register(NetBoxSSLTags.netbox_ssl)
def check_plugin_ready(app_configs, **kwargs):
    """Comprehensive check that the plugin is ready for use."""
    infos = []

    try:
        from netbox_ssl.models import Certificate, CertificateAssignment

        # Count existing data
        cert_count = Certificate.objects.count()
        assignment_count = CertificateAssignment.objects.count()

        infos.append(
            Info(
                f"NetBox SSL Plugin Status: {cert_count} certificates, {assignment_count} assignments",
                hint="Plugin is installed and database is accessible.",
                id="netbox_ssl.I001",
            )
        )

        # Check for expiring certificates
        from datetime import timedelta

        from django.utils import timezone

        expiring_soon = Certificate.objects.filter(
            status="active",
            valid_to__lte=timezone.now() + timedelta(days=30),
            valid_to__gt=timezone.now(),
        ).count()

        if expiring_soon > 0:
            infos.append(
                Warning(
                    f"{expiring_soon} certificate(s) expiring within 30 days",
                    hint="Review expiring certificates and plan renewals.",
                    id="netbox_ssl.W007",
                )
            )

        # Check for expired certificates
        expired = Certificate.objects.filter(
            status="active",
            valid_to__lt=timezone.now(),
        ).count()

        if expired > 0:
            infos.append(
                Warning(
                    f"{expired} certificate(s) have expired but are still marked as active",
                    hint="Update the status of expired certificates.",
                    id="netbox_ssl.W008",
                )
            )

    except Exception as e:
        error_msg = str(e)
        if "does not exist" in error_msg:
            # Tables not yet created — friendly message for fresh installs
            infos.append(
                Info(
                    "Plugin not yet initialized. Run: python manage.py migrate netbox_ssl",
                    hint=f"Database details: {error_msg}",
                    id="netbox_ssl.I003",
                )
            )
        else:
            infos.append(
                Warning(
                    f"Could not perform plugin health check: {error_msg}",
                    id="netbox_ssl.W009",
                )
            )

    return infos


@register(Tags.database)
def check_database_integrity(app_configs, **kwargs):
    """Check database integrity for certificate data."""
    issues = []

    try:
        from netbox_ssl.models import Certificate, CertificateAssignment

        # Check for orphaned assignments (pointing to deleted objects)
        try:
            orphaned = 0
            for assignment in CertificateAssignment.objects.select_related("assigned_object_type").iterator():
                if assignment.assigned_object is None:
                    orphaned += 1
            if orphaned > 0:
                issues.append(
                    Warning(
                        f"Found {orphaned} orphaned assignment(s) pointing to deleted objects.",
                        hint="These assignments reference objects that no longer exist. "
                        "Consider deleting them via the admin interface.",
                        id="netbox_ssl.W010",
                    )
                )
        except Exception:
            pass  # Table may not exist yet

        # Check for duplicate serial_number + issuer combinations
        try:
            from django.db.models import Count

            duplicates = (
                Certificate.objects.values("serial_number", "issuer").annotate(count=Count("id")).filter(count__gt=1)
            )
            dup_count = duplicates.count()
            if dup_count > 0:
                issues.append(
                    Warning(
                        f"Found {dup_count} duplicate serial_number + issuer combination(s).",
                        hint="This may indicate duplicate certificate imports. Review and remove duplicates.",
                        id="netbox_ssl.W011",
                    )
                )
        except Exception:
            pass  # Table may not exist yet

    except Exception:
        pass  # Models not available

    return issues
