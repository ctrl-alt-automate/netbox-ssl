"""Regression guard: custom permission codenames must be grantable in NetBox.

NetBox does not use Django's own permission tables. Its
``ObjectPermissionMixin`` (netbox/netbox/authentication/__init__.py) fully
overrides ``get_all_permissions`` and builds the set of permissions a user
holds *exclusively* from ``ObjectPermission.actions``::

    perm_name = f"{object_type.app_label}.{action}_{object_type.model}"

and ``utilities.permissions.resolve_permission`` takes a codename apart again
with::

    action, model_name = codename.rsplit('_', 1)

Two consequences follow, and both bit this plugin (issue #166):

1. Ticking a permission in a Django group or role grants nothing. A permission
   is granted only by an ObjectPermission carrying the bare *action* verb.
2. The text after the final underscore must name a real model in the app.
   ``bulk_operations`` would require a model called ``operations``,
   ``manage_compliance`` a model called ``compliance``, and ``run_urlimport``
   a model called ``urlimport``. No such models exist, so NetBox can never
   construct those permission names -- they were ungrantable to every
   non-superuser, silently, since v0.9.

This guard parses ``Meta.permissions`` out of the model modules with AST (the
host unit lane cannot import the models, which need NetBox) and asserts every
codename decomposes into an action plus a model this app actually defines.
"""

from __future__ import annotations

import ast

import pytest

from .conftest import get_plugin_source_dir

_MODEL_BASE_NAMES = {
    "NetBoxModel",
    "Model",
    "models.Model",
    "ChangeLoggedModel",
    "PrimaryModel",
    "OrganizationalModel",
    "NestedGroupModel",
}


def _base_name(base: ast.expr) -> str:
    """Return a comparable name for a class base node."""
    if isinstance(base, ast.Attribute):
        return f"{getattr(base.value, 'id', '')}.{base.attr}".lstrip(".")
    return getattr(base, "id", "")


def _model_classes(tree: ast.Module) -> list[ast.ClassDef]:
    """Return the Django model classes defined at module level."""
    return [
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and any(_base_name(b) in _MODEL_BASE_NAMES for b in node.bases)
    ]


def _meta_permissions(cls: ast.ClassDef) -> list[str]:
    """Return the codenames declared in ``cls.Meta.permissions``."""
    codenames: list[str] = []
    for meta in cls.body:
        if not (isinstance(meta, ast.ClassDef) and meta.name == "Meta"):
            continue
        for stmt in meta.body:
            if not (
                isinstance(stmt, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "permissions" for t in stmt.targets)
                and isinstance(stmt.value, ast.List | ast.Tuple)
            ):
                continue
            for entry in stmt.value.elts:
                if isinstance(entry, ast.List | ast.Tuple) and entry.elts:
                    first = entry.elts[0]
                    if isinstance(first, ast.Constant) and isinstance(first.value, str):
                        codenames.append(first.value)
    return codenames


def _collect() -> tuple[set[str], dict[str, str]]:
    """Return ``(model_names, {codename: owning_model})`` for the plugin's models."""
    models_dir = get_plugin_source_dir() / "models"
    assert models_dir.is_dir(), f"models dir not found: {models_dir}"

    model_names: set[str] = set()
    declared: dict[str, str] = {}

    for py_file in sorted(models_dir.glob("*.py")):
        tree = ast.parse(py_file.read_text(), filename=py_file.name)
        for cls in _model_classes(tree):
            model_names.add(cls.name.lower())
            for codename in _meta_permissions(cls):
                declared[codename] = cls.name.lower()

    return model_names, declared


@pytest.mark.unit
def test_custom_permissions_decompose_to_a_real_model() -> None:
    """Every custom permission must be expressible as ``<action>_<model>`` (issue #166)."""
    model_names, declared = _collect()
    assert declared, "no custom permissions found — has Meta.permissions moved?"

    broken: list[str] = []
    for codename, owner in sorted(declared.items()):
        if "_" not in codename:
            broken.append(f"{codename} (on {owner}) has no '_' separator, so it cannot decompose at all")
            continue
        action, model_name = codename.rsplit("_", 1)
        if model_name not in model_names:
            broken.append(
                f"{codename} (on {owner}) decomposes to action={action!r} + model={model_name!r}, "
                f"but this app defines no model named {model_name!r}"
            )

    assert not broken, (
        "NetBox builds permission names as '<app>.<action>_<model>' from "
        "ObjectPermission.actions, so a codename whose suffix is not a real model "
        "can never be granted to a non-superuser:\n  " + "\n  ".join(broken)
    )


@pytest.mark.unit
def test_permission_checks_in_code_reference_declared_permissions() -> None:
    """Every ``has_perm("netbox_ssl.X")`` must name a permission the models declare."""
    import re

    model_names, declared = _collect()
    source_root = get_plugin_source_dir()

    # Django creates add/change/delete/view for every model automatically.
    builtin = {f"{action}_{model}" for action in ("add", "change", "delete", "view") for model in model_names}
    known = builtin | set(declared)

    pattern = re.compile(r"""has_perm\(\s*["']netbox_ssl\.([a-z_]+)["']""")
    unknown: list[str] = []

    for py_file in sorted(source_root.rglob("*.py")):
        if "migrations" in py_file.parts:
            continue
        for line_no, line in enumerate(py_file.read_text().splitlines(), start=1):
            for codename in pattern.findall(line):
                if codename not in known:
                    rel = py_file.relative_to(source_root)
                    unknown.append(f"{rel}:{line_no} checks undeclared permission netbox_ssl.{codename}")

    assert not unknown, (
        "These permission checks name a codename that no model declares, so they "
        "deny every non-superuser unconditionally:\n  " + "\n  ".join(unknown)
    )
