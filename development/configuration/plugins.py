# NetBox SSL Plugin Configuration for Development

PLUGINS = [
    "netbox_ssl",
]

PLUGINS_CONFIG = {
    "netbox_ssl": {
        "expiry_warning_days": 30,
        "expiry_critical_days": 14,
    },
}
