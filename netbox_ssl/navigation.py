"""
Navigation menu configuration for NetBox SSL plugin.
"""

from netbox.plugins import PluginMenu, PluginMenuButton, PluginMenuItem

menu = PluginMenu(
    label="SSL Certificates",
    groups=(
        (
            "Certificates",
            (
                PluginMenuItem(
                    link="plugins:netbox_ssl:certificate_list",
                    link_text="Certificates",
                    permissions=["netbox_ssl.view_certificate"],
                    buttons=(
                        PluginMenuButton(
                            link="plugins:netbox_ssl:certificate_add",
                            title="Add",
                            icon_class="mdi mdi-plus-thick",
                            permissions=["netbox_ssl.add_certificate"],
                        ),
                    ),
                ),
                PluginMenuItem(
                    link="plugins:netbox_ssl:certificate_import",
                    link_text="Import Certificate",
                    permissions=["netbox_ssl.add_certificate"],
                ),
                PluginMenuItem(
                    link="plugins:netbox_ssl:certificateassignment_list",
                    link_text="Assignments",
                    permissions=["netbox_ssl.view_certificateassignment"],
                    buttons=(
                        PluginMenuButton(
                            link="plugins:netbox_ssl:certificateassignment_add",
                            title="Add",
                            icon_class="mdi mdi-plus-thick",
                            permissions=["netbox_ssl.add_certificateassignment"],
                        ),
                    ),
                ),
            ),
        ),
    ),
    icon_class="mdi mdi-certificate",
)
