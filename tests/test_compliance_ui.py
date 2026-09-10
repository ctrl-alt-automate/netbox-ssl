"""Tests for the CompliancePolicy / ComplianceCheck presentation layer (#164).

The compliance models, filtersets and REST API shipped in v0.7, but no forms,
tables, views, URLs or menu entries were ever written. Both models nevertheless
declare ``get_absolute_url()`` pointing at ``plugins:netbox_ssl:compliancepolicy``
and ``...:compliancecheck``, so any template that linked to one raised
``NoReverseMatch``.

The URL/menu assertions are source-level so they run in the host unit lane,
where NetBox is not importable; the form and checker tests need the ORM and are
marked ``django_db``.
"""

from __future__ import annotations

import pytest

from .conftest import get_plugin_source_dir


def _read(relative: str) -> str:
    return (get_plugin_source_dir() / relative).read_text()


@pytest.mark.unit
class TestComplianceUrlsExist:
    """The URLs the models' get_absolute_url() already pointed at must resolve."""

    def test_policy_urls_are_registered(self):
        urls = _read("urls.py")
        for name in (
            "compliancepolicy_list",
            "compliancepolicy_add",
            "compliancepolicy_bulk_delete",
            "compliancepolicy_edit",
            "compliancepolicy_delete",
            "compliancepolicy_changelog",
        ):
            assert f'name="{name}"' in urls, f"missing URL: {name}"
        assert 'name="compliancepolicy",' in urls, "missing detail URL: compliancepolicy"

    def test_check_urls_are_registered(self):
        urls = _read("urls.py")
        for name in ("compliancecheck_list", "compliancecheck_bulk_delete", "compliancecheck_changelog"):
            assert f'name="{name}"' in urls, f"missing URL: {name}"
        assert 'name="compliancecheck",' in urls, "missing detail URL: compliancecheck"

    def test_get_absolute_url_targets_have_routes(self):
        """Every reverse() target named in the models must exist in urls.py."""
        import re

        models_source = _read("models/compliance.py")
        urls = _read("urls.py")
        targets = re.findall(r'reverse\(\s*"plugins:netbox_ssl:([a-z_]+)"', models_source)
        assert targets, "no reverse() targets found in models/compliance.py"
        for target in targets:
            assert f'name="{target}"' in urls, f"models reverse to '{target}' but no such URL is registered"


@pytest.mark.unit
class TestComplianceNavigation:
    """Policies must be reachable from the menu, which is what #164 reported."""

    def test_menu_exposes_policies_and_checks(self):
        nav = _read("navigation.py")
        assert "compliancepolicy_list" in nav
        assert "compliancecheck_list" in nav

    def test_menu_add_button_is_permission_gated(self):
        nav = _read("navigation.py")
        assert "netbox_ssl.add_compliancepolicy" in nav
        assert "netbox_ssl.view_compliancepolicy" in nav


@pytest.mark.unit
class TestComplianceViewsWiring:
    """The view classes must be exported so urls.py can reference them."""

    def test_views_are_exported(self):
        exports = _read("views/__init__.py")
        for name in (
            "CompliancePolicyListView",
            "CompliancePolicyView",
            "CompliancePolicyEditView",
            "CompliancePolicyDeleteView",
            "CompliancePolicyBulkDeleteView",
            "ComplianceCheckListView",
            "ComplianceCheckView",
            "ComplianceCheckBulkDeleteView",
        ):
            assert name in exports, f"view not exported: {name}"

    def test_check_views_offer_no_create_or_edit(self):
        """Check results are produced by the checker, never typed in by hand."""
        source = _read("views/compliance.py")
        assert "class ComplianceCheckEditView" not in source
        assert "ComplianceCheckForm" not in source

    def test_detail_view_restricts_the_related_checks(self):
        source = _read("views/compliance.py")
        assert 'restrict(request.user, "view")' in source


@pytest.mark.django_db
class TestCompliancePolicyForm:
    """Parameters are consumed as a mapping, so the form must enforce that."""

    def test_valid_parameters_are_accepted(self):
        from netbox_ssl.forms import CompliancePolicyForm

        form = CompliancePolicyForm(
            data={
                "name": "RSA min key size 2048",
                "policy_type": "min_key_size",
                "severity": "critical",
                "enabled": True,
                "parameters": '{"min_bits": 2048}',
            }
        )
        assert form.is_valid(), form.errors
        assert form.cleaned_data["parameters"] == {"min_bits": 2048}

    def test_empty_parameters_default_to_an_empty_dict(self):
        from netbox_ssl.forms import CompliancePolicyForm

        form = CompliancePolicyForm(
            data={
                "name": "Chain required",
                "policy_type": "chain_required",
                "severity": "warning",
                "enabled": True,
                "parameters": "",
            }
        )
        assert form.is_valid(), form.errors
        assert form.cleaned_data["parameters"] == {}

    def test_non_object_parameters_are_rejected(self):
        """A JSON list would blow up later in policy.parameters.get()."""
        from netbox_ssl.forms import CompliancePolicyForm

        form = CompliancePolicyForm(
            data={
                "name": "Bad params",
                "policy_type": "min_key_size",
                "severity": "critical",
                "enabled": True,
                "parameters": "[2048]",
            }
        )
        assert not form.is_valid()
        assert "parameters" in form.errors


@pytest.mark.unit
class TestDocumentedChoicesExist:
    """The how-to must only name choice values the ChoiceSets actually define.

    The guide told readers to set a severity of ``Error``; the choices are
    Critical, Warning and Info, so the documented value was unusable and the
    API example it showed would have been rejected. Same class of drift as the
    documented API URLs in #165 -- prose that nothing verifies against the code.
    """

    def _choice_values(self, class_name: str) -> set[str]:
        import ast

        tree = ast.parse(_read("models/compliance.py"))
        for cls in tree.body:
            if isinstance(cls, ast.ClassDef) and cls.name == class_name:
                return {
                    node.value
                    for stmt in cls.body
                    if isinstance(stmt, ast.Assign)
                    for node in ast.walk(stmt)
                    if isinstance(node, ast.Constant) and isinstance(node.value, str)
                }
        raise AssertionError(f"{class_name} not found in models/compliance.py")

    def _how_to(self) -> str:
        docs = get_plugin_source_dir().parent / "docs" / "how-to" / "compliance-policies.md"
        if not docs.is_file():
            pytest.skip("docs/ not available (in-container runs copy only tests/)")
        return docs.read_text()

    def test_documented_severity_values_exist(self):
        import re

        valid = self._choice_values("ComplianceSeverityChoices")
        used = set(re.findall(r'"severity":\s*"([a-z_]+)"', self._how_to()))
        unknown = sorted(used - valid)
        assert not unknown, f"how-to names severity values that do not exist: {unknown} (valid: {sorted(valid)})"

    def test_documented_policy_types_exist(self):
        import re

        valid = self._choice_values("CompliancePolicyTypeChoices")
        used = set(re.findall(r'"policy_type":\s*"([a-z_]+)"', self._how_to()))
        unknown = sorted(used - valid)
        assert not unknown, f"how-to names policy types that do not exist: {unknown}"


@pytest.mark.unit
class TestTableActionsAreReversible:
    """Every action a table renders must have a registered URL.

    ``NetBoxTable`` attaches an ``ActionsColumn`` which defaults to
    ``('edit', 'delete', 'changelog')`` and calls ``reverse()`` for each action on
    **every row**. A missing view does not degrade gracefully: it raises
    ``NoReverseMatch``, which 500s the entire list page -- and any HTMX fragment
    that embeds it.

    This bit the compliance check list, where the deliberate design decision
    "check results have no edit form" left `compliancecheck_edit` unreversible.
    The existing tests asserted that no edit view exists, which is the opposite
    of the property that matters: the list must *render*.

    Only reachable by running the real UI, so this guard encodes it statically.
    """

    _DEFAULT_ACTIONS = ("edit", "delete", "changelog")

    def _table_actions(self) -> list[tuple[str, str, tuple[str, ...]]]:
        """Return ``(file, model_name, actions)`` for every table in the plugin."""
        import ast

        results = []
        for py_file in sorted((get_plugin_source_dir() / "tables").glob("*.py")):
            tree = ast.parse(py_file.read_text(), filename=py_file.name)
            for cls in tree.body:
                if not isinstance(cls, ast.ClassDef):
                    continue
                if not any(getattr(b, "id", getattr(b, "attr", None)) == "NetBoxTable" for b in cls.bases):
                    continue

                model = None
                actions = self._DEFAULT_ACTIONS
                for node in cls.body:
                    # class Meta: model = X
                    if isinstance(node, ast.ClassDef) and node.name == "Meta":
                        for stmt in node.body:
                            if (
                                isinstance(stmt, ast.Assign)
                                and any(isinstance(t, ast.Name) and t.id == "model" for t in stmt.targets)
                                and isinstance(stmt.value, ast.Name)
                            ):
                                model = stmt.value.id.lower()
                    # actions = columns.ActionsColumn(actions=(...))
                    if (
                        isinstance(node, ast.Assign)
                        and any(isinstance(t, ast.Name) and t.id == "actions" for t in node.targets)
                        and isinstance(node.value, ast.Call)
                    ):
                        for kw in node.value.keywords:
                            if kw.arg == "actions" and isinstance(kw.value, ast.List | ast.Tuple):
                                actions = tuple(
                                    e.value
                                    for e in kw.value.elts
                                    if isinstance(e, ast.Constant) and isinstance(e.value, str)
                                )
                if model:
                    results.append((py_file.name, model, actions))
        return results

    def test_every_rendered_action_has_a_url(self):
        urls = _read("urls.py")
        tables = self._table_actions()
        assert tables, "no NetBoxTable subclasses found — has the tables package moved?"

        missing = [
            f"{file}: {model} table renders '{action}' but no URL named '{model}_{action}' is registered"
            for file, model, actions in tables
            for action in actions
            if f'name="{model}_{action}"' not in urls
        ]

        assert not missing, (
            "NetBoxTable's ActionsColumn reverses every action it renders, so a missing "
            "URL raises NoReverseMatch and 500s the whole list page:\n  " + "\n  ".join(missing)
        )
