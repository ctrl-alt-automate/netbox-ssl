# NetBox SSL Plugin Configuration for Development

import os

PLUGINS = [
    "netbox_ssl",
]

PLUGINS_CONFIG = {
    "netbox_ssl": {
        "expiry_warning_days": 30,
        "expiry_critical_days": 14,
    },
}

# API Token Peppers for v2 tokens (v4.5+ requires dictionary, min 50 chars)
# Load from environment variable for security
_pepper = os.environ.get("API_TOKEN_PEPPER_1")
if _pepper:
    API_TOKEN_PEPPERS = {1: _pepper}
