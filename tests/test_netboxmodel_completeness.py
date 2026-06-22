"""Completeness invariants that must hold for EVERY NetBoxModel in the plugin.

These guard two recurring bug classes that have repeatedly shipped because the
lenient NetBox version under local testing hid them:

1. **Missing REST serializer (#149).** When a NetBoxModel is saved in a request
   context, NetBox's change-logging machinery calls
   ``serialize_for_event`` → ``get_serializer_for_model``. A model with no
   registered serializer raises ``SerializerNotFound`` — a *hard* error on
   NetBox 4.4 (4.5/4.6 are lenient, so a local 4.5/4.6 run never trips it).
   "Skip the API as YAGNI" is therefore invalid for a NetBoxModel.

2. **Migration drift vs the NetBoxModel parent (#118 / v1.0.1).** ``NetBoxModel``
   adds ``custom_field_data`` + ``tags``; a model whose migration was frozen at
   ``models.Model`` lacks those columns and 500s at runtime.

Both checks are version-independent and run on every NetBox version in the
integration matrix (and are wired into the "regression gates must run" bundle so
a silent skip cannot hide them).
"""

import importlib.util

import pytest

# Guard: these need a real NetBox. The host unit lane mocks ``netbox`` in
# sys.modules, so find_spec hits a Mock ``__spec__`` and raises ValueError —
# treat that as "not available" rather than crashing collection.
try:
    _NETBOX_AVAILABLE = importlib.util.find_spec("netbox") is not None
except (ValueError, ModuleNotFoundError):
    _NETBOX_AVAILABLE = False

if not _NETBOX_AVAILABLE:
    pytest.skip("NetBox not available — skipping NetBoxModel completeness tests", allow_module_level=True)


def _plugin_netboxmodels():
    """Every concrete (non-abstract) NetBoxModel subclass declared by the plugin."""
    from django.apps import apps
    from netbox.models import NetBoxModel

    return [
        model
        for model in apps.get_models()
        if model._meta.app_label == "netbox_ssl" and issubclass(model, NetBoxModel) and not model._meta.abstract
    ]


@pytest.mark.django_db
class TestNetBoxModelCompleteness:
    def test_models_were_discovered(self):
        # Guard against the introspection silently finding nothing (which would
        # make the assertions below vacuously pass).
        assert _plugin_netboxmodels(), "No netbox_ssl NetBoxModel subclasses discovered — introspection is broken."

    def test_every_netboxmodel_has_a_registered_serializer(self):
        from utilities.api import get_serializer_for_model

        missing = []
        for model in _plugin_netboxmodels():
            try:
                get_serializer_for_model(model)
            except Exception:  # noqa: BLE001 - SerializerNotFound (and any lookup failure) means "no serializer"
                missing.append(model.__name__)

        assert not missing, (
            f"NetBoxModel(s) with no registered REST API serializer: {missing}. "
            "NetBox serializes a model for change-log events on save "
            "(serialize_for_event → get_serializer_for_model); a missing serializer "
            "raises SerializerNotFound on NetBox 4.4. Add a serializer + viewset + "
            "router registration (mirror an existing one, e.g. ExternalSource)."
        )

    def test_every_netboxmodel_carries_custom_fields_and_tags(self):
        missing = []
        for model in _plugin_netboxmodels():
            field_names = {f.name for f in model._meta.get_fields()}
            if "custom_field_data" not in field_names or "tags" not in field_names:
                missing.append(model.__name__)

        assert not missing, (
            f"NetBoxModel(s) missing custom_field_data/tags: {missing}. A migration "
            "frozen at models.Model (before the NetBoxModel mixin was added) lacks "
            "these columns and 500s at runtime — regenerate the migration."
        )
