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

import importlib.util

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
def test_plugin_serializer_method_fields_are_typed():
    """Every plugin SerializerMethodField must be schema-typed (#119).

    drf-spectacular warns (and, under the CI ``--fail-on-warn`` gate, fails) for
    any ``SerializerMethodField`` whose ``get_<field>`` resolver lacks a return
    type hint or an ``@extend_schema_field``. This is a fast, deterministic guard
    that mirrors that contract at the source level — unlike scraping
    drf-spectacular's internal warning state, it cannot silently pass.
    """
    import inspect

    from rest_framework.fields import SerializerMethodField

    from netbox_ssl.api import serializers as ssl_serializers

    serializer_classes = [
        obj
        for _, obj in inspect.getmembers(ssl_serializers, inspect.isclass)
        if obj.__module__.startswith("netbox_ssl")
    ]

    offenders = []
    for ser_class in serializer_classes:
        try:
            fields = ser_class().fields
        except Exception:
            # Serializers needing request context etc. — inspect declared fields.
            fields = getattr(ser_class, "_declared_fields", {})
        for field_name, field in fields.items():
            if not isinstance(field, SerializerMethodField):
                continue
            method_name = field.method_name or f"get_{field_name}"
            method = getattr(ser_class, method_name, None)
            if method is None:
                continue
            has_hint = "return" in getattr(method, "__annotations__", {})
            has_extend = hasattr(method, "_spectacular_annotation")
            if not (has_hint or has_extend):
                offenders.append(f"{ser_class.__name__}.{method_name}")

    assert not offenders, (
        "SerializerMethodField resolvers must declare a return type hint or "
        "@extend_schema_field so the OpenAPI schema generates warning-free "
        "(CI runs --fail-on-warn); offending: " + "; ".join(sorted(set(offenders)))
    )


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
