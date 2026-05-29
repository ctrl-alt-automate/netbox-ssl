"""
Regression tests for security invariants that previously had ZERO coverage.

This plugin is the source of truth for TLS-certificate metadata, so a handful
of security controls must never silently regress:

1. CSV formula-injection sanitization (``CertificateExporter._sanitize_csv_value``)
   — an exported CSV opened in a spreadsheet must not execute injected formulas.
2. Custom (non-NetBox-generic) views must enforce authentication via
   ``LoginRequiredMixin`` — a dropped mixin would expose a view to anonymous
   users. (NetBox's own generic views carry their own object-permission
   enforcement and are excluded.)

Requires a real NetBox/Django environment; runs in the Docker integration job.
"""

import contextlib
import importlib
import importlib.util
import inspect
import os
import pkgutil
import sys
from pathlib import Path

import pytest

_root = Path(__file__).parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

try:
    _spec = importlib.util.find_spec("netbox")
    NETBOX_AVAILABLE = _spec is not None and _spec.origin is not None
except (ValueError, ModuleNotFoundError):
    NETBOX_AVAILABLE = False

if NETBOX_AVAILABLE:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "netbox.settings")
    import django

    with contextlib.suppress(Exception):
        django.setup()

requires_netbox = pytest.mark.skipif(
    not NETBOX_AVAILABLE,
    reason="NetBox not available - run these tests inside the Docker container",
)

# Spreadsheet formula-trigger characters (mirrors CertificateExporter._FORMULA_CHARS).
_FORMULA_CHARS = ["=", "+", "-", "@", "\t", "\r"]


@requires_netbox
@pytest.mark.parametrize("trigger", _FORMULA_CHARS)
def test_csv_value_with_formula_char_is_neutralized(trigger):
    """A value starting with a formula trigger must be prefixed with a quote."""
    from netbox_ssl.utils.export import CertificateExporter

    payload = f"{trigger}cmd|'/bin/calc'!A0"
    sanitized = CertificateExporter._sanitize_csv_value(payload)
    assert sanitized == "'" + payload, f"value starting with {trigger!r} was not neutralized: {sanitized!r}"


@requires_netbox
def test_csv_safe_values_are_unchanged():
    """Non-formula values must pass through untouched."""
    from netbox_ssl.utils.export import CertificateExporter

    for safe in ["example.com", "CN=Test CA", "", "2048", "RSA"]:
        assert CertificateExporter._sanitize_csv_value(safe) == safe


@requires_netbox
def test_custom_views_require_login():
    """Every custom (non-NetBox-generic) view must include LoginRequiredMixin.

    NetBox's generic Object*View classes enforce object permissions themselves;
    our bespoke TemplateView/View subclasses (analytics, compliance report,
    certificate map, import/renew flows) must not be reachable anonymously.
    """
    from django.contrib.auth.mixins import LoginRequiredMixin
    from django.views.generic.base import View

    import netbox_ssl.views as views_pkg

    missing = []
    seen = set()
    for mod_info in pkgutil.iter_modules(views_pkg.__path__):
        module = importlib.import_module(f"netbox_ssl.views.{mod_info.name}")
        for name, cls in inspect.getmembers(module, inspect.isclass):
            if cls in seen:
                continue
            seen.add(cls)
            if not issubclass(cls, View):
                continue
            if not (cls.__module__ or "").startswith("netbox_ssl"):
                continue
            # NetBox generic views (ObjectView/ObjectEditView/...) carry their own
            # ObjectPermissionRequiredMixin — they are not our responsibility.
            if any("netbox.views.generic" in (base.__module__ or "") for base in cls.__mro__):
                continue
            if LoginRequiredMixin not in cls.__mro__:
                missing.append(f"{cls.__module__}.{name}")

    assert not missing, f"custom views missing LoginRequiredMixin (anonymous access risk): {missing}"
