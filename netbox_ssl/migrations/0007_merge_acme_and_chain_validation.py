from django.db import migrations


class Migration(migrations.Migration):
    """Merge the ACME tracking and chain validation migration branches."""

    dependencies = [
        ("netbox_ssl", "0003_certificate_acme_tracking"),
        ("netbox_ssl", "0006_certificate_chain_validation"),
    ]

    operations = []
