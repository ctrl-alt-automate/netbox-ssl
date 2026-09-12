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

This stays hidden in the in-container lane because that lane copies only
`tests/` into the container (see `conftest.get_plugin_source_dir`) -- the
`.github/` directory never makes it in. Module-skip when the workflow file is
absent, the same pattern `test_script_objectvar.py` uses for its own
repo-file dependency (issue: reading a repo file outside `tests/` cost this
project a CI round before, see MEMORY.md's release-readiness-gates entry).
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

if not _WORKFLOW_PATH.is_file():
    pytest.skip(
        f"{_WORKFLOW_PATH} not found -- expected in the in-container lane, "
        "which copies only tests/ (see conftest.get_plugin_source_dir).",
        allow_module_level=True,
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
