"""
Add ``certificate_type`` to Certificate (#168).

Records whether a certificate is used for server authentication, client
authentication, or both (mutual TLS). The value is derived from the X.509
Extended Key Usage extension on import and can be overridden by an operator.

Additive and reversible: a new CharField with a default, indexed for filtering.
Existing rows take the ``server`` default, which matches how the plugin has
treated every certificate up to now.
"""

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_ssl", "0026_grantable_custom_permissions"),
    ]

    operations = [
        migrations.AddField(
            model_name="certificate",
            name="certificate_type",
            field=models.CharField(
                choices=[("server", "Server"), ("client", "Client"), ("mtls", "mTLS")],
                db_index=True,
                default="server",
                help_text="Role in the TLS handshake; detected from Extended Key Usage on import",
                max_length=20,
            ),
        ),
    ]
