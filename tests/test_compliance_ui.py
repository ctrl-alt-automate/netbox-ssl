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
                "severity": "error",
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
                "severity": "error",
                "enabled": True,
                "parameters": "[2048]",
            }
        )
        assert not form.is_valid()
        assert "parameters" in form.errors
