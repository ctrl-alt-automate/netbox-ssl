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

# API Token Peppers for v2 tokens (v4.5+ requires dictionary, min 50 chars)
API_TOKEN_PEPPERS = {
    1: "Eb_30LtX2Rz01aSiZ29i8IwRyrbyy-maTokgIzAzADCt78gtlu5jd6EY1wGlX7RJ4XvpjRdLsyc4jnwj",
}
