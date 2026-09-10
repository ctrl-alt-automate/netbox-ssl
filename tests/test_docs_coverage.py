"""Guard the reference documentation against drifting behind the code.

Every feature shipped since v0.8 arrived with its own how-to guide, but the
*reference* documents — the ones describing the whole surface rather than one
task — were barely touched. By v1.4 that left seven models and ten REST
endpoints undocumented, including `MonitoredEndpoint`, the headline feature of
v1.3.0, and `assign-targets`, a REST action added in the same release.

The drift is structural rather than careless: when you add a feature you write
the guide that belongs to it, and the overview document belongs to nobody. So
these tests make the overview documents an enforced invariant — a new model or
endpoint without a reference entry fails the build.

AST- and regex-based, so they run in the host unit lane without NetBox.
"""

from __future__ import annotations

import ast
import re

import pytest

from .conftest import get_plugin_source_dir

# Base classes whose subclasses are user-visible models worth documenting.
_MODEL_BASES = {"NetBoxModel", "Model", "models.Model"}

# Internal models that carry no user-facing surface.
_EXEMPT_MODELS: set[str] = set()


def _repo_root():
    return get_plugin_source_dir().parent


def _docs(*parts: str) -> str | None:
    path = _repo_root().joinpath("docs", *parts)
    return path.read_text() if path.is_file() else None


def _plugin_models() -> set[str]:
    models = set()
    for py_file in sorted((get_plugin_source_dir() / "models").glob("*.py")):
        for cls in ast.parse(py_file.read_text()).body:
            if isinstance(cls, ast.ClassDef) and any(
                (b.attr if isinstance(b, ast.Attribute) else getattr(b, "id", "")) in _MODEL_BASES for b in cls.bases
            ):
                models.add(cls.name)
    return models - _EXEMPT_MODELS


@pytest.mark.unit
def test_every_model_is_in_the_data_model_reference():
    """A model users can see must have a section in data-models.md."""
    doc = _docs("reference", "data-models.md")
    if doc is None:
        pytest.skip("docs/ not available (in-container runs copy only tests/)")

    # Require an actual "## <Model>" section, not merely the name appearing
    # somewhere: "MonitoredEndpoint" is a substring of
    # "MonitoredEndpointCertificate", so a substring test reports a deleted
    # section as documented.
    documented = set(re.findall(r"(?m)^## (\w+)", doc))
    missing = sorted(m for m in _plugin_models() if m not in documented)
    assert not missing, "these models have no entry in docs/reference/data-models.md:\n  " + "\n  ".join(missing)


@pytest.mark.unit
def test_every_rest_collection_is_in_the_api_reference():
    """Every registered router collection must appear in api.md."""
    doc = _docs("reference", "api.md")
    if doc is None:
        pytest.skip("docs/ not available (in-container runs copy only tests/)")

    api_urls = (get_plugin_source_dir() / "api" / "urls.py").read_text()
    registered = set(re.findall(r'router\.register\(\s*"([\w-]+)"', api_urls))
    missing = sorted(route for route in registered if f"/{route}/" not in doc)
    assert not missing, (
        "these REST collections are registered but absent from docs/reference/api.md:\n  " + "\n  ".join(missing)
    )


@pytest.mark.unit
def test_every_custom_api_action_is_in_the_api_reference():
    """Custom @action endpoints are the least discoverable part of the API."""
    doc = _docs("reference", "api.md")
    if doc is None:
        pytest.skip("docs/ not available (in-container runs copy only tests/)")

    views = (get_plugin_source_dir() / "api" / "views.py").read_text()
    actions = set(re.findall(r'url_path="([\w-]+)"', views))
    missing = sorted(action for action in actions if action not in doc)
    assert not missing, "these custom API actions are undocumented in docs/reference/api.md:\n  " + "\n  ".join(missing)


@pytest.mark.unit
def test_reference_docs_only_name_models_that_exist():
    """Catch the reverse drift: documentation describing something removed.

    `docs/explanation/architecture.md` named `ComplianceResult` in its ER
    diagram for several releases; the model is called `ComplianceCheck`.
    """
    known = _plugin_models() | {
        # NetBox core models the plugin relates to.
        "Certificate",
        "Device",
        "VirtualMachine",
        "Service",
        "Tenant",
        "Tag",
        "User",
    }
    offenders: list[str] = []
    for name in ("data-models.md", "api.md"):
        doc = _docs("reference", name)
        if doc is None:
            pytest.skip("docs/ not available (in-container runs copy only tests/)")
        for match in re.findall(r"(?m)^## (\w+)", doc):
            # Section headings that look like a model name must be a real model.
            if re.match(r"^(Certificate|Compliance|External|Monitored)\w+$", match) and match not in known:
                offenders.append(f"reference/{name}: '## {match}' is not a model in netbox_ssl.models")

    doc = _docs("explanation", "architecture.md")
    if doc is not None:
        er = re.search(r"```mermaid\s+erDiagram(.*?)```", doc, re.S)
        if er:
            for entity in set(re.findall(r"\b([A-Z]\w+)\b", er.group(1))):
                if entity not in known:
                    offenders.append(f"explanation/architecture.md: ER diagram names unknown entity '{entity}'")

    assert not offenders, "documentation names things that do not exist:\n  " + "\n  ".join(offenders)
