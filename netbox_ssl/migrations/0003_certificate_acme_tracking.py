"""
Migration to add ACME certificate tracking fields.

Adds fields to track ACME-issued certificates and their renewal settings.
"""

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_ssl", "0002_certificate_sans_gin_index"),
    ]

    operations = [
        migrations.AddField(
            model_name="certificate",
            name="is_acme",
            field=models.BooleanField(
                default=False,
                help_text="Whether this certificate was issued via ACME protocol",
            ),
        ),
        migrations.AddField(
            model_name="certificate",
            name="acme_provider",
            field=models.CharField(
                blank=True,
                choices=[
                    ("letsencrypt", "Let's Encrypt"),
                    ("letsencrypt_staging", "Let's Encrypt (Staging)"),
                    ("zerossl", "ZeroSSL"),
                    ("buypass", "Buypass"),
                    ("google", "Google Trust Services"),
                    ("digicert", "DigiCert"),
                    ("sectigo", "Sectigo"),
                    ("other", "Other"),
                ],
                help_text="ACME provider (e.g., Let's Encrypt, ZeroSSL)",
                max_length=30,
            ),
        ),
        migrations.AddField(
            model_name="certificate",
            name="acme_account_email",
            field=models.EmailField(
                blank=True,
                help_text="Email address associated with the ACME account",
            ),
        ),
        migrations.AddField(
            model_name="certificate",
            name="acme_challenge_type",
            field=models.CharField(
                blank=True,
                choices=[
                    ("http-01", "HTTP-01"),
                    ("dns-01", "DNS-01"),
                    ("tls-alpn-01", "TLS-ALPN-01"),
                    ("unknown", "Unknown"),
                ],
                help_text="Challenge type used for domain validation",
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name="certificate",
            name="acme_server_url",
            field=models.URLField(
                blank=True,
                help_text="ACME server URL (e.g., https://acme-v02.api.letsencrypt.org/directory)",
                max_length=500,
            ),
        ),
        migrations.AddField(
            model_name="certificate",
            name="acme_auto_renewal",
            field=models.BooleanField(
                default=False,
                help_text="Whether automatic renewal is configured",
            ),
        ),
        migrations.AddField(
            model_name="certificate",
            name="acme_last_renewed",
            field=models.DateTimeField(
                blank=True,
                help_text="When this certificate was last renewed via ACME",
                null=True,
            ),
        ),
        migrations.AddField(
            model_name="certificate",
            name="acme_renewal_days",
            field=models.PositiveSmallIntegerField(
                blank=True,
                default=30,
                help_text="Days before expiry to attempt renewal",
                null=True,
            ),
        ),
    ]
