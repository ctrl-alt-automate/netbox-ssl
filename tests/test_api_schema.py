"""
Regression tests for OpenAPI (drf-spectacular) schema generation — issue #111.

NetBox 4.6's ``core/api/schema.py`` made ``/api/schema/`` (the REST API
Swagger UI) crash with ``ValueError: too many values to unpack (expected 2,
got 3)`` whenever a plugin FilterSet declared a ``MultipleChoiceFilter`` with a
*raw* colored ChoiceSet list (``SomeChoiceSet.CHOICES`` — 3-tuples of
``(value, label, color)``). drf-spectacular's ``_get_explicit_filter_choices``
does ``[c for c, _ in filter_field.extra['choices']]`` and cannot unpack
3-tuples, which aborts generation of the *entire* schema — so installing the
plugin broke Swagger for the whole NetBox instance.

Two guards:

1. ``test_openapi_schema_generation_succeeds`` — builds the full schema exactly
   like the ``/api/schema/`` endpoint; this reproduced #111 (it raised) and now
   must succeed.
2. ``test_plugin_filtersets_choices_are_spectacular_safe`` — a fast, targeted
   guard asserting every plugin filter's choices are either *callable* (a
   ChoiceSet class) or plain 2-tuples — never raw colored 3-tuples.

These require a real NetBox/Django environment and run inside the Docker
integration job; they skip elsewhere.
"""

import contextlib
import os
import sys
from pathlib import Path

import pytest

# Allow importing the plugin package directly.
_project_root = Path(__file__).parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

_in_netbox_env = os.path.exists("/opt/netbox/netbox/netbox/settings.py") or "DJANGO_SETTINGS_MODULE" in os.environ

if _in_netbox_env:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "netbox.settings")
    import django

    with contextlib.suppress(RuntimeError):
        django.setup()
    NETBOX_AVAILABLE = True
else:
    NETBOX_AVAILABLE = False

requires_netbox = pytest.mark.skipif(
    not NETBOX_AVAILABLE,
    reason="NetBox not available - run these tests inside the Docker container",
)


@requires_netbox
def test_openapi_schema_generation_succeeds():
    """The full OpenAPI schema must generate without raising (regression #111).

    Before the fix, ``SchemaGenerator.get_schema`` raised ``ValueError: too
    many values to unpack (expected 2, got 3)`` while resolving the compliance
    filterset's choice parameters, taking down ``/api/schema/`` entirely.
    """
    from drf_spectacular.generators import SchemaGenerator

    generator = SchemaGenerator()
    schema = generator.get_schema(request=None, public=True)

    assert schema, "schema generation returned an empty document"
    paths = schema.get("paths", {})
    ssl_paths = [p for p in paths if "/plugins/ssl/" in p]
    assert ssl_paths, "no netbox_ssl paths present in the generated OpenAPI schema"


@requires_netbox
def test_plugin_filtersets_choices_are_spectacular_safe():
    """No plugin filter may expose raw colored (3-tuple) choices (#111).

    drf-spectacular's ``_get_explicit_filter_choices`` skips *callable* choices
    (a ChoiceSet class) but unpacks non-callable choices as 2-tuples. Passing
    ``ChoiceSet.CHOICES`` (which include a colour) therefore crashes schema
    generation. Always pass the ChoiceSet *class*, not ``.CHOICES``.
    """
    import inspect

    import django_filters

    from netbox_ssl import filtersets as ssl_filtersets

    filterset_classes = [
        obj
        for _, obj in inspect.getmembers(ssl_filtersets, inspect.isclass)
        if issubclass(obj, django_filters.FilterSet) and obj.__module__.startswith("netbox_ssl")
    ]
    assert filterset_classes, "no plugin FilterSet classes were discovered"

    offenders = []
    for fs_class in filterset_classes:
        for field_name, filter_field in fs_class.base_filters.items():
            choices = getattr(filter_field, "extra", {}).get("choices")
            if choices is None or callable(choices):
                continue
            for entry in choices:
                if not (isinstance(entry, (list, tuple)) and len(entry) == 2):
                    offenders.append(f"{fs_class.__name__}.{field_name} -> {entry!r}")

    assert not offenders, (
        "Filter choices must be a callable ChoiceSet class or 2-tuples so "
        "drf-spectacular can build the schema; offending filters: " + "; ".join(offenders)
    )
