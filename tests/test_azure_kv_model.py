"""Model-level additions for the Azure Key Vault adapter (#101).

`netbox_ssl.models` cannot be imported on the host lane — Django models need
configured settings — so the shape assertions read the model source, the same
way tests/test_permission_names.py does. The behavioural assertion that the
default actually applies runs in the container lane.

Every assertion here parses the AST rather than grepping for substrings. WHY:
a substring test over module text is satisfied by a comment, a docstring, or a
mention in an unrelated help string, so it stays green while the feature is
broken — `assert "sync_tags" in source` passed for the form, serializer and
GraphQL type whether or not any of them actually exposed the field (#101
review M8). The AST helpers below only see real declarations: a choice tuple,
a field assignment, a member of a `fields` list. This is the pattern
tests/test_script_objectvar.py established for exactly this reason.
"""

import ast
from pathlib import Path

import pytest

from .conftest import get_plugin_source_dir

# get_plugin_source_dir(), not Path(__file__).parent.parent: the container lane
# copies tests to /tmp/plugin_tests/ while the plugin lives at
# /opt/netbox/netbox/netbox_ssl/, so the hand-rolled form resolved to a path
# that does not exist and every test here died with FileNotFoundError instead
# of asserting anything (#101 review C3).
_PLUGIN = get_plugin_source_dir()
MODEL_SOURCE = _PLUGIN / "models" / "external_source.py"


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(), filename=str(path))


def _find_class(tree: ast.Module, class_name: str) -> ast.ClassDef:
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            return node
    raise AssertionError(f"class {class_name} not found")


def _choice_pairs(class_name: str) -> dict[str, str]:
    """Return {value: label} for a ChoiceSet's CHOICES list.

    Resolves the ``TYPE_X = "x"`` constants the CHOICES tuples refer to, so the
    pairing is checked — not merely that both strings appear somewhere in the
    class body. The old helper collected every string constant in every
    assignment, which could not tell "Azure Key Vault" labelling `azure_kv`
    from "Azure Key Vault" labelling anything else.
    """
    cls = _find_class(_parse(MODEL_SOURCE), class_name)

    constants: dict[str, str] = {}
    choices_node: ast.AST | None = None
    for stmt in cls.body:
        if not isinstance(stmt, ast.Assign):
            continue
        for target in stmt.targets:
            if not isinstance(target, ast.Name):
                continue
            if target.id == "CHOICES":
                choices_node = stmt.value
            elif isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str):
                constants[target.id] = stmt.value.value

    assert isinstance(choices_node, (ast.List, ast.Tuple)), f"{class_name}.CHOICES is not a literal list"

    def _resolve(node: ast.AST) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            return constants.get(node.id)
        return None

    pairs: dict[str, str] = {}
    for element in choices_node.elts:
        if not isinstance(element, (ast.Tuple, ast.List)) or len(element.elts) < 2:
            continue
        value, label = _resolve(element.elts[0]), _resolve(element.elts[1])
        if value is not None and label is not None:
            pairs[value] = label
    return pairs


def _field_keywords(class_name: str, field_name: str) -> dict[str, ast.AST]:
    """Return the keyword arguments of ``<class>.<field> = models.X(...)``.

    Raises if the field is not a model-field call at all, so a stray mention in
    a comment or a plain string assignment cannot satisfy the test.
    """
    cls = _find_class(_parse(MODEL_SOURCE), class_name)
    for stmt in cls.body:
        if not isinstance(stmt, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == field_name for t in stmt.targets):
            continue
        call = stmt.value
        assert isinstance(call, ast.Call), f"{class_name}.{field_name} is not a model field call"
        func = call.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
        assert name and name.endswith("Field"), f"{class_name}.{field_name} is a {name}, not a model field"
        return {kw.arg: kw.value for kw in call.keywords if kw.arg}
    raise AssertionError(f"{class_name} declares no field named {field_name}")


def _string_members(node: ast.AST | None) -> set[str]:
    """Return the string constants of a literal list/tuple node."""
    if not isinstance(node, (ast.List, ast.Tuple)):
        return set()
    return {e.value for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}


def _meta_fields(relative: str, class_name: str) -> set[str]:
    """Return ``<class_name>.Meta.fields`` for a form or serializer.

    Scoped to the named class on purpose: a module-wide search would accept the
    field appearing on some *other* form or serializer in the same file.
    """
    cls = _find_class(_parse(_PLUGIN / relative), class_name)
    meta = next((n for n in cls.body if isinstance(n, ast.ClassDef) and n.name == "Meta"), None)
    assert meta is not None, f"{class_name} has no Meta class"
    for stmt in meta.body:
        if isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "fields" for t in stmt.targets):
            return _string_members(stmt.value)
    raise AssertionError(f"{class_name}.Meta declares no fields list")


def _graphql_type_fields(class_name: str) -> set[str]:
    """Return the explicit field list on a ``@strawberry_django.type(...)`` class.

    The list is a decorator keyword, not an assignment, and it must be read
    from THIS class: the review of this branch noted that git's hunk header
    made the new entry look like it had landed on CertificateAuthorityType. A
    module-wide search would have been unable to tell the difference.
    """
    cls = _find_class(_parse(_PLUGIN / "graphql" / "types.py"), class_name)
    for decorator in cls.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        for kw in decorator.keywords:
            if kw.arg == "fields":
                return _string_members(kw.value)
    raise AssertionError(f"{class_name} has no decorator declaring an explicit fields list")


@pytest.mark.unit
def test_azure_kv_source_type_exists():
    assert "azure_kv" in _choice_pairs("ExternalSourceTypeChoices")


@pytest.mark.unit
def test_azure_kv_has_a_human_label():
    """A choice value with no label renders as a raw slug in the UI."""
    assert _choice_pairs("ExternalSourceTypeChoices")["azure_kv"] == "Azure Key Vault"


@pytest.mark.unit
def test_sync_tags_is_a_boolean_field_defaulting_to_false():
    """Opt-in by construction: upgrading must not start writing tags.

    Checked here as well as at runtime below because the runtime test only
    runs in the container lane — the one the host matrix cannot see.
    """
    keywords = _field_keywords("ExternalSource", "sync_tags")
    default = keywords.get("default")
    assert isinstance(default, ast.Constant) and default.value is False, (
        "sync_tags must declare default=False; tag syncing is opt-in"
    )


@pytest.mark.unit
def test_sync_tags_is_editable():
    """A field the form cannot render is not an opt-in, it is a dead column."""
    editable = _field_keywords("ExternalSource", "sync_tags").get("editable")
    assert editable is None or (isinstance(editable, ast.Constant) and editable.value is True), (
        "sync_tags is declared editable=False, so no operator can turn tag syncing on"
    )


@pytest.mark.django_db
def test_sync_tags_defaults_to_false():
    """The runtime counterpart: the field as Django actually resolves it."""
    from netbox_ssl.models import ExternalSource

    field = ExternalSource._meta.get_field("sync_tags")
    assert field.default is False
    assert field.editable is True


@pytest.mark.unit
class TestSyncTagsIsOperable:
    """A model field nobody can set is not a feature."""

    def test_form_exposes_sync_tags(self):
        assert "sync_tags" in _meta_fields("forms/external_sources.py", "ExternalSourceForm")

    def test_serializer_exposes_sync_tags(self):
        assert "sync_tags" in _meta_fields("api/serializers/external_sources.py", "ExternalSourceSerializer")

    def test_graphql_exposes_sync_tags(self):
        assert "sync_tags" in _graphql_type_fields("ExternalSourceType")
