"""
NetBox SSL diagnostics command.

Provides a comprehensive overview of the plugin state for support and troubleshooting.

Usage: python manage.py ssl_diagnostics
"""

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Display NetBox SSL plugin diagnostics for troubleshooting"

    def handle(self, *args, **options):
        self.stdout.write(self.style.MIGRATE_HEADING("\n=== NetBox SSL Diagnostics ===\n"))

        self._show_versions()
        self._show_migration_status()
        self._show_certificate_stats()
        self._show_health_checks()

    def _show_versions(self):
        self.stdout.write(self.style.MIGRATE_HEADING("Versions:"))
        try:
            import netbox_ssl

            self.stdout.write(f"  Plugin version: {netbox_ssl.__version__}")
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"  Plugin version: ERROR — {e}"))

        try:
            import netbox

            version = ".".join(str(v) for v in netbox.VERSION)
            self.stdout.write(f"  NetBox version: {version}")
        except Exception:
            self.stdout.write("  NetBox version: unknown")

        try:
            import sys

            self.stdout.write(f"  Python version: {sys.version.split()[0]}")
        except Exception:
            pass

        self.stdout.write("")

    def _show_migration_status(self):
        self.stdout.write(self.style.MIGRATE_HEADING("Migration status:"))
        try:
            from django.db import connection
            from django.db.migrations.recorder import MigrationRecorder

            recorder = MigrationRecorder(connection)
            applied = recorder.applied_migrations()
            plugin_migrations = {k: v for k, v in applied.items() if k[0] == "netbox_ssl"}
            self.stdout.write(f"  Applied migrations: {len(plugin_migrations)}")

            # Find latest migration
            if plugin_migrations:
                latest = max(plugin_migrations.keys(), key=lambda x: x[1])
                self.stdout.write(f"  Latest migration: {latest[1]}")
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"  Migration check failed: {e}"))

        self.stdout.write("")

    def _show_certificate_stats(self):
        self.stdout.write(self.style.MIGRATE_HEADING("Certificate statistics:"))
        try:
            from netbox_ssl.models import Certificate, CertificateAssignment

            total = Certificate.objects.count()
            active = Certificate.objects.filter(status="active").count()
            expired = Certificate.objects.filter(status="expired").count()
            acme = Certificate.objects.filter(is_acme=True).count()
            assignments = CertificateAssignment.objects.count()

            self.stdout.write(f"  Total certificates: {total}")
            self.stdout.write(f"  Active: {active}")
            self.stdout.write(f"  Expired: {expired}")
            self.stdout.write(f"  ACME managed: {acme}")
            self.stdout.write(f"  Assignments: {assignments}")
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"  Stats unavailable: {e}"))

        self.stdout.write("")

    def _show_health_checks(self):
        self.stdout.write(self.style.MIGRATE_HEADING("Health checks:"))
        try:
            from django.core import checks

            all_issues = checks.run_checks(tags=["netbox_ssl"])
            if not all_issues:
                self.stdout.write(self.style.SUCCESS("  All checks passed"))
            else:
                for issue in all_issues:
                    level = issue.level_tag.upper()
                    if issue.level >= checks.ERROR:
                        self.stdout.write(self.style.ERROR(f"  [{level}] {issue.msg}"))
                    elif issue.level >= checks.WARNING:
                        self.stdout.write(self.style.WARNING(f"  [{level}] {issue.msg}"))
                    else:
                        self.stdout.write(f"  [{level}] {issue.msg}")
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"  Health check failed: {e}"))

        self.stdout.write("")
