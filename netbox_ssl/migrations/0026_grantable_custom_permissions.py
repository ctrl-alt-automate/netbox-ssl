"""
Rename three custom permissions so NetBox can actually grant them (#166).

NetBox builds the set of permissions a user holds exclusively from
``ObjectPermission.actions``::

    perm_name = f"{object_type.app_label}.{action}_{object_type.model}"

and takes a codename apart again with ``codename.rsplit('_', 1)``. The suffix
after the final underscore must therefore name a real model in the app.

``bulk_operations`` implied a model called ``operations``, ``manage_compliance``
a model called ``compliance``, and ``run_urlimport`` a model called
``urlimport``. None exist, so NetBox could never construct those names and the
three permissions were ungrantable to every non-superuser — silently, since
v0.9. They are renamed to the ``<action>_<model>`` form:

    bulk_operations   -> bulk_certificate          (action "bulk")
    run_urlimport     -> urlimport_certificate     (action "urlimport")
    manage_compliance -> manage_compliancepolicy   (action "manage")

Metadata-only and reversible: this alters ``Meta.permissions``, which Django
stores in ``auth_permission``. No data migration is required, because no
ObjectPermission could ever have referenced the old names.
"""

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_ssl", "0025_monitored_endpoint"),
    ]

    operations = [
        migrations.AlterModelOptions(
            name="certificate",
            options={
                "ordering": ["-valid_to", "common_name"],
                "permissions": [
                    ("import_certificate", "Can import certificates from PEM/DER/PKCS7"),
                    ("renew_certificate", "Can perform certificate renewal"),
                    ("bulk_certificate", "Can perform bulk certificate operations"),
                    ("urlimport_certificate", "Can run URL certificate import"),
                ],
            },
        ),
        migrations.AlterModelOptions(
            name="compliancepolicy",
            options={
                "ordering": ["name"],
                "permissions": [
                    ("manage_compliancepolicy", "Can run compliance checks and manage policies"),
                ],
                "verbose_name_plural": "compliance policies",
            },
        ),
    ]
