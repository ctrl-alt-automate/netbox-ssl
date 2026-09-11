"""Model-level additions for the Azure Key Vault adapter (#101).

`netbox_ssl.models` cannot be imported on the host lane — Django models need
configured settings — so the shape assertions read the model source, the same
way tests/test_permission_names.py does. The behavioural assertion that the
default actually applies runs in the container lane.
"""

import ast
from pathlib import Path

import pytest

MODEL_SOURCE = Path(__file__).parent.parent / "netbox_ssl" / "models" / "external_source.py"


def _choice_values(class_name: str) -> set[str]:
    """Return every string constant assigned inside a ChoiceSet class."""
    tree = ast.parse(MODEL_SOURCE.read_text())
    for cls in tree.body:
        if isinstance(cls, ast.ClassDef) and cls.name == class_name:
            return {
                node.value
                for stmt in cls.body
                if isinstance(stmt, ast.Assign)
                for node in ast.walk(stmt)
                if isinstance(node, ast.Constant) and isinstance(node.value, str)
            }
    raise AssertionError(f"{class_name} not found in {MODEL_SOURCE.name}")


@pytest.mark.unit
def test_azure_kv_source_type_exists():
    assert "azure_kv" in _choice_values("ExternalSourceTypeChoices")


@pytest.mark.unit
def test_azure_kv_has_a_human_label():
    """A choice value with no label renders as a raw slug in the UI."""
    assert "Azure Key Vault" in _choice_values("ExternalSourceTypeChoices")


@pytest.mark.unit
def test_sync_tags_field_is_declared():
    assert "sync_tags = models.BooleanField(" in MODEL_SOURCE.read_text()


@pytest.mark.django_db
def test_sync_tags_defaults_to_false():
    """Opt-in: upgrading must never start writing tags to existing certificates."""
    from netbox_ssl.models import ExternalSource

    field = ExternalSource._meta.get_field("sync_tags")
    assert field.default is False
