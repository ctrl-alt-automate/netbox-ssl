"""Add custom permissions for import, renewal, bulk, and compliance operations."""

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_ssl", "0014_merge_v080"),
    ]

    operations = [
        migrations.AlterModelOptions(
            name="certificate",
            options={
                "ordering": ["-valid_to", "common_name"],
                "permissions": [
                    ("import_certificate", "Can import certificates from PEM/DER/PKCS7"),
                    ("renew_certificate", "Can perform certificate renewal"),
                    ("bulk_operations", "Can perform bulk certificate operations"),
                ],
            },
        ),
        migrations.AlterModelOptions(
            name="compliancepolicy",
            options={
                "ordering": ["name"],
                "verbose_name_plural": "compliance policies",
                "permissions": [
                    ("manage_compliance", "Can run compliance checks and manage policies"),
                ],
            },
        ),
    ]
