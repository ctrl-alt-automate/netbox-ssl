"""Regression guard for the Azure live-test privilege-canary declaration.

`tests/test_azure_kv_live.py`'s privilege canary
(`test_private_key_is_unreachable`) only runs for real when
`AZURE_KV_LEAST_PRIVILEGE_IDENTITY=1` is set -- an earlier attempt to
auto-detect the CI identity from `GITHUB_ACTIONS` + `AZURE_CLIENT_ID` turned
out to be based on a false premise (`azure/login@v2` never exports
`AZURE_CLIENT_ID` into the job environment), so the canary skipped in CI
forever, silently. The fix moved to an explicit declaration in
`.github/workflows/azure-integration.yml`'s "Live adapter tests" step.

An explicit declaration someone later deletes (refactor, copy-paste, a well
-meaning `env:` cleanup) fails exactly the same silent way: the canary just
skips again, and nothing turns red. This test reads the actual workflow YAML
and fails loudly if that declaration is ever removed from the step that runs
`test_azure_kv_live.py`.

The workflow-reading test stays hidden in the in-container lane because that
lane copies only `tests/` into the container (see
`conftest.get_plugin_source_dir`) -- the `.github/` directory never makes it
in. It skips when the workflow file is absent, the same pattern
`test_script_objectvar.py` uses for its own repo-file dependency (issue:
reading a repo file outside `tests/` cost this project a CI round before, see
MEMORY.md's release-readiness-gates entry).

The file also guards the *other* half of the live-test lane contract: that
`conftest.pytest_collection_modifyitems` keeps `azure_live` tests out of every
lane that did not select them (#101 review C5). That test reads no repo file,
so it runs everywhere -- including the container lane it protects.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit

# tests/ is directly under the repo root locally; in the Docker container lane
# this file lives at /tmp/plugin_tests/ with no .github/ sibling at all, so
# the file simply won't exist there -- handled by the skip below, not by
# trying to guess a container-side path the way conftest.get_plugin_source_dir
# does for the plugin source (there is no equivalent "workflows in the
# container" location; they never ship there).
_WORKFLOW_PATH = Path(__file__).parent.parent / ".github" / "workflows" / "azure-integration.yml"

# A per-test skipif rather than a module-level skip: the conftest gating test
# below reads no repo file and MUST run in the in-container lane, because that
# lane is precisely the one the gate protects.
_requires_workflow_file = pytest.mark.skipif(
    not _WORKFLOW_PATH.is_file(),
    reason=(
        f"{_WORKFLOW_PATH} not found -- expected in the in-container lane, "
        "which copies only tests/ (see conftest.get_plugin_source_dir)."
    ),
)


def _find_live_test_step(workflow: dict) -> dict:
    """Return the step dict whose `run:` invokes test_azure_kv_live.py."""
    for job in workflow.get("jobs", {}).values():
        for step in job.get("steps", []):
            if "test_azure_kv_live.py" in step.get("run", ""):
                return step
    raise AssertionError(
        f"No step running test_azure_kv_live.py found in {_WORKFLOW_PATH}. "
        "Either the workflow was restructured or the live tests were removed "
        "from it -- either way, the privilege canary's CI trigger is gone."
    )


@_requires_workflow_file
def test_live_test_step_declares_least_privilege_identity() -> None:
    """The step running the live tests must set AZURE_KV_LEAST_PRIVILEGE_IDENTITY.

    Without this, test_private_key_is_unreachable's canary silently skips in
    CI forever -- exactly the failure mode this guard exists to catch (see
    the module docstring).
    """
    workflow = yaml.safe_load(_WORKFLOW_PATH.read_text())
    step = _find_live_test_step(workflow)

    env = step.get("env", {})
    assert "AZURE_KV_LEAST_PRIVILEGE_IDENTITY" in env, (
        "The step running test_azure_kv_live.py no longer sets "
        "AZURE_KV_LEAST_PRIVILEGE_IDENTITY in its env: block. Without it, "
        "test_private_key_is_unreachable silently skips in CI forever -- it "
        "never verifies the CI service principal's role. Restore "
        '`AZURE_KV_LEAST_PRIVILEGE_IDENTITY: "1"` on that step (see '
        "azure-integration.yml's comment for the RBAC justification)."
    )
    # YAML env values are commonly quoted strings; compare as a string so a
    # bare `1` (parsed as int by PyYAML) still fails loudly rather than
    # passing on a type technicality -- os.environ values are always strings
    # anyway, so "1" is the only value that actually gates the canary open.
    assert str(env["AZURE_KV_LEAST_PRIVILEGE_IDENTITY"]) == "1", (
        f"AZURE_KV_LEAST_PRIVILEGE_IDENTITY is set to "
        f'{env["AZURE_KV_LEAST_PRIVILEGE_IDENTITY"]!r}, not "1" -- '
        "test_private_key_is_unreachable's gate only opens on the exact "
        'string "1" (os.environ.get(...) == "1").'
    )


def test_conftest_deselects_azure_live_outside_an_explicit_selection() -> None:
    """The live tests must never be collected by a lane that did not ask for them.

    The marker on tests/test_azure_kv_live.py *selects* those tests in the
    Azure workflow; it excludes them nowhere. The in-container integration lane
    runs the whole directory with no ``-m`` filter, so before the conftest hook
    it executed them against the maintainer's real Key Vault (#101 review C5).

    This asserts the hook's actual behaviour -- deselect without ``-m
    azure_live``, keep with it -- rather than merely grepping conftest for the
    function name, and it deliberately runs in EVERY lane, including the
    container one it protects.
    """
    from .conftest import pytest_collection_modifyitems

    class _Item:
        def __init__(self, live: bool) -> None:
            self._live = live

        def get_closest_marker(self, name: str):
            return object() if (self._live and name == "azure_live") else None

    class _Hook:
        def __init__(self) -> None:
            self.deselected: list = []

        def pytest_deselected(self, items) -> None:
            self.deselected.extend(items)

    class _Config:
        def __init__(self, markexpr: str) -> None:
            self._markexpr = markexpr
            self.hook = _Hook()

        def getoption(self, name, default=None):
            return self._markexpr if name == "markexpr" else default

    live, ordinary = _Item(live=True), _Item(live=False)

    # No -m filter: the in-container lane. The live item must be dropped.
    config = _Config("")
    items = [live, ordinary]
    pytest_collection_modifyitems(config, items)
    assert items == [ordinary], "azure_live tests are still collected by a lane that did not select them"
    assert config.hook.deselected == [live], "deselected items were not reported to pytest"

    # -m unit: the host lane. Same outcome.
    items = [live, ordinary]
    pytest_collection_modifyitems(_Config("unit"), items)
    assert items == [ordinary]

    # -m azure_live: the maintainer's local command and the workflow's own
    # invocation. The live item must survive.
    items = [live, ordinary]
    pytest_collection_modifyitems(_Config("azure_live"), items)
    assert items == [live, ordinary], "-m azure_live no longer selects the live tests"
