# Multi-Object Certificate Assignment (#148) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an operator assign one certificate to many Devices/VMs/Services in a single action, from the certificate detail page and via the REST API.

**Architecture:** A single shared service function `assign_certificate_to_targets()` is the source of truth (idempotent, atomic, skip-duplicates). A new `detail=True` REST action and a cert-centric UI form/view are thin adapters over it. No database migration — the `CertificateAssignment` M2M model already supports one cert → many objects.

**Tech Stack:** Django, NetBox plugin framework, Django REST Framework, NetBox `DynamicModelMultipleChoiceField`, pytest (`@pytest.mark.django_db`).

## Global Constraints

- **NetBox compatibility:** 4.4–4.6; **Python:** 3.10–3.12.
- **Spec:** `project-requirement-document/specs/2026-06-19-148-multi-object-assignment-design.md`.
- **No database migration.** The data model is unchanged.
- **Security (v0.7.5 rules):** custom view uses `LoginRequiredMixin` as first base class; every queryset uses `.restrict(request.user, "view")`; writes are gated on `netbox_ssl.add_certificateassignment`; DB exceptions are logged internally and returned as a generic message (never `str(e)` of a DB error).
- **Idempotency:** assigning a target that is already assigned is **not** an error — it is silently skipped and counted (mirrors the existing `bulk_assign` action).
- **`is_primary` default:** `False`.
- **Batch cap:** `PLUGINS_CONFIG["netbox_ssl"]["bulk_assign_max_batch_size"]` (default `100`).
- **Allowed target content types:** `dcim.device`, `dcim.service`, `virtualization.virtualmachine`.
- **Style:** PEP 8, type annotations on signatures, black/isort/ruff clean.
- **Cross-tenant assignments:** out of scope for this feature — matches the existing `bulk_assign` behaviour, which creates rows directly without invoking `CertificateAssignment.clean()`. (Noted as a possible follow-up; not implemented here.)

## Test Execution

The service, API, and view all touch the ORM, so their tests are
`@pytest.mark.django_db` and run **inside the NetBox Docker container** (per
`CLAUDE.md` §"Tests in Docker Container"). Source files are hot-mounted; **test
files AND `pytest.ini` must be copied in before each run** — `pytest.ini` is
what supplies `DJANGO_SETTINGS_MODULE=netbox.settings`, without which
pytest-django will not configure. The canonical run command used throughout
this plan (the per-step `docker cp tests/...` lines below are shorthand for it):

```bash
docker cp tests/. netbox-ssl-netbox-1:/tmp/plugin_tests/ \
  && docker cp pytest.ini netbox-ssl-netbox-1:/tmp/plugin_tests/pytest.ini \
  && docker exec netbox-ssl-netbox-1 /opt/netbox/venv/bin/python -m pytest /tmp/plugin_tests/<FILE> -v --tb=short
```

Note: each run takes ~90s — pytest-django rebuilds NetBox's (large) migration
set for the test database. This is normal; be patient rather than assuming a
hang.

One-time container prep (already done for this environment; recorded for
reproducibility — the venv lacks `ensurepip`, so bootstrap pip via get-pip):

```bash
docker exec netbox-ssl-netbox-1 bash -c "curl -sS https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py && /opt/netbox/venv/bin/python /tmp/get-pip.py"
docker exec netbox-ssl-netbox-1 /opt/netbox/venv/bin/python -m pip install pytest pytest-django
```

## File Structure

| File | Responsibility |
|------|----------------|
| `netbox_ssl/utils/assignments.py` | **new** — `AssignResult`, `AssignmentError`, `assign_certificate_to_targets()`. The only place that creates assignment rows in bulk. |
| `netbox_ssl/utils/__init__.py` | export the service symbols |
| `netbox_ssl/api/serializers/certificates.py` | **new** `AssignTargetSerializer` + `AssignTargetsSerializer` |
| `netbox_ssl/api/serializers/__init__.py` | export `AssignTargetsSerializer` |
| `netbox_ssl/api/views.py` | new `assign-targets` `detail=True` action on `CertificateViewSet` |
| `netbox_ssl/forms/assignments.py` | **new** `CertificateBulkAssignForm` |
| `netbox_ssl/forms/__init__.py` | export `CertificateBulkAssignForm` |
| `netbox_ssl/views/assignments.py` | **new** `CertificateAssignTargetsView` |
| `netbox_ssl/views/__init__.py` | export `CertificateAssignTargetsView` |
| `netbox_ssl/urls.py` | new `certificates/<int:pk>/assign-targets/` route |
| `netbox_ssl/templates/netbox_ssl/certificate_assign_targets.html` | **new** form page |
| `netbox_ssl/templates/netbox_ssl/certificate.html` | "Assign to objects" button in the detail header |
| `tests/test_assignments_service.py` | **new** — service unit tests |
| `tests/test_api_endpoints.py` | add `assign-targets` API tests |
| `tests/test_assign_targets_view.py` | **new** — form/view tests |
| `CHANGELOG.md` | `Unreleased` → Added entry |

---

## Task 1: Shared assignment service

**Files:**
- Create: `netbox_ssl/utils/assignments.py`
- Modify: `netbox_ssl/utils/__init__.py`
- Test: `tests/test_assignments_service.py`

**Interfaces:**
- Produces:
  - `class AssignmentError(Exception)` — domain error carrying a user-safe message.
  - `@dataclass(frozen=True) class AssignResult` with fields `created: int`, `skipped: int`, `created_targets: tuple[str, ...]`, `skipped_targets: tuple[str, ...]`.
  - `assign_certificate_to_targets(certificate, targets, *, is_primary: bool = False) -> AssignResult` where `targets: Sequence[tuple[ContentType, int]]`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_assignments_service.py`:

```python
"""Unit tests for the bulk certificate-assignment service."""

import pytest
from django.contrib.contenttypes.models import ContentType


@pytest.mark.django_db
class TestAssignCertificateToTargets:
    def _make_cert(self):
        from netbox_ssl.models import Certificate

        return Certificate.objects.create(
            common_name="*.example.com",
            serial_number="01:AA",
            issuer="Test CA",
            valid_from="2026-01-01T00:00:00Z",
            valid_to="2027-01-01T00:00:00Z",
        )

    def _device(self, name):
        from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site

        site = Site.objects.create(name=f"site-{name}", slug=f"site-{name}")
        mfr = Manufacturer.objects.create(name=f"mfr-{name}", slug=f"mfr-{name}")
        dtype = DeviceType.objects.create(manufacturer=mfr, model=f"model-{name}", slug=f"model-{name}")
        role = DeviceRole.objects.create(name=f"role-{name}", slug=f"role-{name}")
        return Device.objects.create(name=name, site=site, device_type=dtype, role=role)

    def test_creates_assignments_for_each_target(self):
        from netbox_ssl.models import CertificateAssignment
        from netbox_ssl.utils.assignments import assign_certificate_to_targets

        cert = self._make_cert()
        d1, d2 = self._device("web01"), self._device("web02")
        ct = ContentType.objects.get_for_model(d1)

        result = assign_certificate_to_targets(cert, [(ct, d1.pk), (ct, d2.pk)])

        assert result.created == 2
        assert result.skipped == 0
        assert CertificateAssignment.objects.filter(certificate=cert).count() == 2
```

- [ ] **Step 2: Run test to verify it fails**

```bash
docker cp tests/. netbox-ssl-netbox-1:/tmp/plugin_tests/ \
  && docker exec netbox-ssl-netbox-1 /opt/netbox/venv/bin/python -m pytest /tmp/plugin_tests/test_assignments_service.py -v
```
Expected: FAIL — `ModuleNotFoundError: No module named 'netbox_ssl.utils.assignments'`.

- [ ] **Step 3: Write minimal implementation**

Create `netbox_ssl/utils/assignments.py`:

```python
"""Service for assigning one certificate to many infrastructure objects.

Single source of truth for the "one cert → many objects" direction, used by
both the REST API action and the UI view. Idempotent: targets already assigned
to the certificate are silently skipped (mirrors the inverse ``bulk_assign``
action).
"""

import logging
from collections.abc import Sequence
from dataclasses import dataclass

from django.contrib.contenttypes.models import ContentType
from django.db import DatabaseError, IntegrityError, transaction

from ..models import CertificateAssignment

logger = logging.getLogger("netbox_ssl.assignments")

# Content-type model names that may receive a certificate assignment.
ALLOWED_ASSIGN_MODELS = ("device", "service", "virtualmachine")


class AssignmentError(Exception):
    """Raised when a bulk assignment cannot be completed. Message is user-safe."""


@dataclass(frozen=True)
class AssignResult:
    created: int
    skipped: int
    created_targets: tuple[str, ...]
    skipped_targets: tuple[str, ...]


def assign_certificate_to_targets(
    certificate,
    targets: Sequence[tuple[ContentType, int]],
    *,
    is_primary: bool = False,
) -> AssignResult:
    """Assign ``certificate`` to each ``(content_type, object_id)`` target.

    Existing assignments are skipped. Raises ``AssignmentError`` on an empty
    target list, an unsupported content type, a missing object, or a database
    error.
    """
    if not targets:
        raise AssignmentError("No assignment targets provided.")

    created = 0
    skipped = 0
    created_targets: list[str] = []
    skipped_targets: list[str] = []

    try:
        with transaction.atomic():
            for content_type, object_id in targets:
                if content_type.model not in ALLOWED_ASSIGN_MODELS:
                    raise AssignmentError(
                        f"Unsupported assignment type: {content_type.app_label}.{content_type.model}"
                    )

                model_class = content_type.model_class()
                if not model_class.objects.filter(pk=object_id).exists():
                    raise AssignmentError(f"{content_type.model} with id {object_id} does not exist.")

                label = f"{content_type.model}:{object_id}"
                already = CertificateAssignment.objects.filter(
                    certificate=certificate,
                    assigned_object_type=content_type,
                    assigned_object_id=object_id,
                ).exists()
                if already:
                    skipped += 1
                    skipped_targets.append(label)
                    continue

                CertificateAssignment.objects.create(
                    certificate=certificate,
                    assigned_object_type=content_type,
                    assigned_object_id=object_id,
                    is_primary=is_primary,
                )
                created += 1
                created_targets.append(label)
    except (IntegrityError, DatabaseError) as exc:
        logger.error("assign_certificate_to_targets failed: %s", exc)
        raise AssignmentError("A database error occurred during assignment.") from exc

    return AssignResult(created, skipped, tuple(created_targets), tuple(skipped_targets))
```

Add to `netbox_ssl/utils/__init__.py` (follow the existing export style in that file):

```python
from .assignments import AssignmentError, AssignResult, assign_certificate_to_targets
```
and add `"AssignmentError"`, `"AssignResult"`, `"assign_certificate_to_targets"` to its `__all__` if one is present.

- [ ] **Step 4: Run test to verify it passes**

```bash
docker cp tests/. netbox-ssl-netbox-1:/tmp/plugin_tests/ \
  && docker exec netbox-ssl-netbox-1 /opt/netbox/venv/bin/python -m pytest /tmp/plugin_tests/test_assignments_service.py -v
```
Expected: PASS (1 passed).

- [ ] **Step 5: Add the remaining behaviour tests**

Append to `TestAssignCertificateToTargets` in `tests/test_assignments_service.py`:

```python
    def test_skips_already_assigned_targets(self):
        from netbox_ssl.utils.assignments import assign_certificate_to_targets

        cert = self._make_cert()
        d1 = self._device("web01")
        ct = ContentType.objects.get_for_model(d1)

        assign_certificate_to_targets(cert, [(ct, d1.pk)])
        result = assign_certificate_to_targets(cert, [(ct, d1.pk)])

        assert result.created == 0
        assert result.skipped == 1
        assert result.skipped_targets == (f"device:{d1.pk}",)

    def test_is_primary_propagates(self):
        from netbox_ssl.models import CertificateAssignment
        from netbox_ssl.utils.assignments import assign_certificate_to_targets

        cert = self._make_cert()
        d1 = self._device("web01")
        ct = ContentType.objects.get_for_model(d1)

        assign_certificate_to_targets(cert, [(ct, d1.pk)], is_primary=True)

        assert CertificateAssignment.objects.get(certificate=cert).is_primary is True

    def test_empty_targets_raises(self):
        from netbox_ssl.utils.assignments import AssignmentError, assign_certificate_to_targets

        cert = self._make_cert()
        with pytest.raises(AssignmentError):
            assign_certificate_to_targets(cert, [])

    def test_missing_object_raises(self):
        from netbox_ssl.utils.assignments import AssignmentError, assign_certificate_to_targets

        cert = self._make_cert()
        d1 = self._device("web01")
        ct = ContentType.objects.get_for_model(d1)
        with pytest.raises(AssignmentError):
            assign_certificate_to_targets(cert, [(ct, d1.pk + 9999)])

    def test_disallowed_content_type_raises(self):
        from netbox_ssl.models import Certificate
        from netbox_ssl.utils.assignments import AssignmentError, assign_certificate_to_targets

        cert = self._make_cert()
        bad_ct = ContentType.objects.get_for_model(Certificate)
        with pytest.raises(AssignmentError):
            assign_certificate_to_targets(cert, [(bad_ct, cert.pk)])
```

- [ ] **Step 6: Run the full service test file**

```bash
docker cp tests/. netbox-ssl-netbox-1:/tmp/plugin_tests/ \
  && docker exec netbox-ssl-netbox-1 /opt/netbox/venv/bin/python -m pytest /tmp/plugin_tests/test_assignments_service.py -v
```
Expected: PASS (6 passed).

- [ ] **Step 7: Lint**

```bash
ruff check netbox_ssl/utils/assignments.py tests/test_assignments_service.py
ruff format --check netbox_ssl/utils/assignments.py tests/test_assignments_service.py
```
Expected: "All checks passed!" and "already formatted".

- [ ] **Step 8: Commit**

```bash
git add netbox_ssl/utils/assignments.py netbox_ssl/utils/__init__.py tests/test_assignments_service.py
git commit -m "feat: add assign_certificate_to_targets bulk-assignment service (#148)"
```

---

## Task 2: REST API action `assign-targets`

**Files:**
- Modify: `netbox_ssl/api/serializers/certificates.py`, `netbox_ssl/api/serializers/__init__.py`
- Modify: `netbox_ssl/api/views.py`
- Test: `tests/test_api_endpoints.py`

**Interfaces:**
- Consumes: `assign_certificate_to_targets`, `AssignmentError`, `AssignResult` from Task 1.
- Produces: `POST /api/plugins/ssl/certificates/{id}/assign-targets`, request body `{"targets": [{"object_type": "dcim.device", "object_id": 42}], "is_primary": false}`, response `{"assigned": int, "skipped": int, "detail": str}`.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_api_endpoints.py` (follow the file's existing API-test fixtures/markers — these tests run against a live API in the integration lane):

```python
@pytest.mark.django_db
class TestAssignTargetsAPI:
    """POST /certificates/{id}/assign-targets — one cert → many objects."""

    def test_assigns_and_skips(self, api_certificate, api_device, drf_admin_client):
        url = f"/api/plugins/ssl/certificates/{api_certificate.pk}/assign-targets/"
        payload = {"targets": [{"object_type": "dcim.device", "object_id": api_device.pk}], "is_primary": False}

        first = drf_admin_client.post(url, payload, format="json")
        assert first.status_code == 200
        assert first.data["assigned"] == 1
        assert first.data["skipped"] == 0

        second = drf_admin_client.post(url, payload, format="json")
        assert second.status_code == 200
        assert second.data["assigned"] == 0
        assert second.data["skipped"] == 1
```

> Reuse the file's existing certificate/device fixtures and authenticated DRF
> client. If `api_device` / `drf_admin_client` do not yet exist, add minimal
> fixtures mirroring the device/client helpers already used by the bulk-assign
> tests in this file.

- [ ] **Step 2: Run test to verify it fails**

```bash
docker cp tests/. netbox-ssl-netbox-1:/tmp/plugin_tests/ \
  && docker exec netbox-ssl-netbox-1 /opt/netbox/venv/bin/python -m pytest /tmp/plugin_tests/test_api_endpoints.py -k TestAssignTargetsAPI -v
```
Expected: FAIL — 404 (the `assign-targets` route does not exist yet).

- [ ] **Step 3: Add the serializers**

Append to `netbox_ssl/api/serializers/certificates.py`:

```python
class AssignTargetSerializer(serializers.Serializer):
    """A single assignment target (content type + object id)."""

    object_type = serializers.CharField(
        help_text="Content type, one of: dcim.device, dcim.service, virtualization.virtualmachine.",
    )
    object_id = serializers.IntegerField(help_text="Primary key of the target object.")


class AssignTargetsSerializer(serializers.Serializer):
    """Assign one certificate to many objects."""

    targets = AssignTargetSerializer(many=True, allow_empty=False)
    is_primary = serializers.BooleanField(default=False)
```

Export both from `netbox_ssl/api/serializers/__init__.py` (add to the import
from `.certificates` and to `__all__`):

```python
    AssignTargetSerializer,
    AssignTargetsSerializer,
```

- [ ] **Step 4: Add the viewset action**

In `netbox_ssl/api/views.py`, add `AssignTargetsSerializer` to the import block
from `.serializers`, and add this import near the other util imports:

```python
from ..utils.assignments import AssignmentError, assign_certificate_to_targets
```

Add the action to `CertificateViewSet` (place it right after `bulk_assign`).
Note: mirrors `bulk_assign`, which carries no `@extend_schema` and passes the
`spectacular --fail-on-warn` gate; if CI flags the new action, add
`@extend_schema(request=AssignTargetsSerializer)` above the decorator.

```python
    @action(detail=True, methods=["post"], url_path="assign-targets")
    def assign_targets(self, request, pk=None):
        """Assign this certificate to multiple objects (Devices, VMs, Services).

        Example payload:
        {
            "targets": [
                {"object_type": "dcim.device", "object_id": 42},
                {"object_type": "dcim.service", "object_id": 7}
            ],
            "is_primary": false
        }
        Duplicate assignments are silently skipped.
        """
        denied = _check_bulk_perm(request, "netbox_ssl.add_certificateassignment")
        if denied:
            return denied

        serializer = AssignTargetsSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        targets_data = serializer.validated_data["targets"]
        is_primary = serializer.validated_data["is_primary"]

        plugin_settings = settings.PLUGINS_CONFIG.get("netbox_ssl", {})
        max_batch_size = plugin_settings.get("bulk_assign_max_batch_size", 100)
        if len(targets_data) > max_batch_size:
            raise serializers.ValidationError(
                {"detail": f"Batch size exceeds maximum of {max_batch_size} targets."}
            )

        certificate = Certificate.objects.restrict(request.user, "view").filter(pk=pk).first()
        if certificate is None:
            return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)

        allowed_types = {"dcim.device", "dcim.service", "virtualization.virtualmachine"}
        resolved: list[tuple[ContentType, int]] = []
        for target in targets_data:
            object_type = target["object_type"]
            if object_type not in allowed_types:
                raise serializers.ValidationError(
                    {"targets": f"Invalid object_type '{object_type}'. Must be one of: {sorted(allowed_types)}"}
                )
            app_label, model = object_type.split(".")
            try:
                content_type = ContentType.objects.get(app_label=app_label, model=model)
            except ContentType.DoesNotExist as exc:
                raise serializers.ValidationError(
                    {"targets": f"Could not resolve content type '{object_type}'."}
                ) from exc
            resolved.append((content_type, target["object_id"]))

        try:
            result = assign_certificate_to_targets(certificate, resolved, is_primary=is_primary)
        except AssignmentError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        return Response(
            {
                "assigned": result.created,
                "skipped": result.skipped,
                "detail": f"Assigned {result.created}, skipped {result.skipped} already assigned.",
            },
            status=status.HTTP_200_OK,
        )
```

- [ ] **Step 5: Run test to verify it passes**

```bash
docker cp tests/. netbox-ssl-netbox-1:/tmp/plugin_tests/ \
  && docker exec netbox-ssl-netbox-1 /opt/netbox/venv/bin/python -m pytest /tmp/plugin_tests/test_api_endpoints.py -k TestAssignTargetsAPI -v
```
Expected: PASS.

- [ ] **Step 6: Add permission + restrict + batch-cap tests**

Append to `TestAssignTargetsAPI`:

```python
    def test_denied_without_add_permission(self, api_certificate, api_device, drf_limited_client):
        url = f"/api/plugins/ssl/certificates/{api_certificate.pk}/assign-targets/"
        payload = {"targets": [{"object_type": "dcim.device", "object_id": api_device.pk}]}
        resp = drf_limited_client.post(url, payload, format="json")
        assert resp.status_code == 403

    def test_invalid_object_type_rejected(self, api_certificate, drf_admin_client):
        url = f"/api/plugins/ssl/certificates/{api_certificate.pk}/assign-targets/"
        payload = {"targets": [{"object_type": "auth.user", "object_id": 1}]}
        resp = drf_admin_client.post(url, payload, format="json")
        assert resp.status_code == 400
```

> `drf_limited_client` = an authenticated client whose user lacks
> `bulk_operations`/`add_certificateassignment`. Mirror the permission-denied
> fixtures already used by the `bulk_assign` tests in this file.

- [ ] **Step 7: Run, lint**

```bash
docker cp tests/. netbox-ssl-netbox-1:/tmp/plugin_tests/ \
  && docker exec netbox-ssl-netbox-1 /opt/netbox/venv/bin/python -m pytest /tmp/plugin_tests/test_api_endpoints.py -k TestAssignTargetsAPI -v
ruff check netbox_ssl/api/views.py netbox_ssl/api/serializers/certificates.py
```
Expected: PASS; "All checks passed!".

- [ ] **Step 8: Commit**

```bash
git add netbox_ssl/api/
git add tests/test_api_endpoints.py
git commit -m "feat: add assign-targets REST action for one cert to many objects (#148)"
```

---

## Task 3: UI form, view, URL, template, detail-page button, changelog

**Files:**
- Modify: `netbox_ssl/forms/assignments.py`, `netbox_ssl/forms/__init__.py`
- Modify: `netbox_ssl/views/assignments.py`, `netbox_ssl/views/__init__.py`
- Modify: `netbox_ssl/urls.py`
- Create: `netbox_ssl/templates/netbox_ssl/certificate_assign_targets.html`
- Modify: `netbox_ssl/templates/netbox_ssl/certificate.html`
- Modify: `CHANGELOG.md`
- Test: `tests/test_assign_targets_view.py`

**Interfaces:**
- Consumes: `assign_certificate_to_targets`, `AssignmentError` from Task 1.
- Produces:
  - `CertificateBulkAssignForm` with fields `devices`, `virtual_machines`, `services`, `is_primary`.
  - `CertificateAssignTargetsView` at URL name `plugins:netbox_ssl:certificate_assign_targets` (`certificates/<int:pk>/assign-targets/`).

- [ ] **Step 1: Write the failing test**

Create `tests/test_assign_targets_view.py`:

```python
"""Tests for the cert-centric bulk-assign form and view."""

import pytest


@pytest.mark.django_db
class TestCertificateBulkAssignForm:
    def test_empty_selection_is_invalid(self):
        from netbox_ssl.forms import CertificateBulkAssignForm

        form = CertificateBulkAssignForm(data={})
        assert not form.is_valid()
        assert "Select at least one" in str(form.errors)
```

- [ ] **Step 2: Run test to verify it fails**

```bash
docker cp tests/. netbox-ssl-netbox-1:/tmp/plugin_tests/ \
  && docker exec netbox-ssl-netbox-1 /opt/netbox/venv/bin/python -m pytest /tmp/plugin_tests/test_assign_targets_view.py -v
```
Expected: FAIL — `ImportError: cannot import name 'CertificateBulkAssignForm'`.

- [ ] **Step 3: Add the form**

Append to `netbox_ssl/forms/assignments.py` (the `Device`, `Service`,
`VirtualMachine`, `forms`, and `_` imports already exist at the top of the file;
add the field import):

```python
from utilities.forms.fields import ContentTypeChoiceField, DynamicModelChoiceField, DynamicModelMultipleChoiceField
```

```python
class CertificateBulkAssignForm(forms.Form):
    """Assign one certificate to many Devices, VMs, and/or Services at once."""

    devices = DynamicModelMultipleChoiceField(
        queryset=Device.objects.all(), required=False, label=_("Devices")
    )
    virtual_machines = DynamicModelMultipleChoiceField(
        queryset=VirtualMachine.objects.all(), required=False, label=_("Virtual Machines")
    )
    services = DynamicModelMultipleChoiceField(
        queryset=Service.objects.all(), required=False, label=_("Services")
    )
    is_primary = forms.BooleanField(
        required=False,
        initial=False,
        label=_("Mark as primary"),
        help_text=_("Mark this certificate as the primary certificate on each selected object."),
    )

    def clean(self):
        cleaned_data = super().clean()
        if not (cleaned_data.get("devices") or cleaned_data.get("virtual_machines") or cleaned_data.get("services")):
            raise forms.ValidationError(_("Select at least one Device, Virtual Machine, or Service."))
        return cleaned_data
```

Export it from `netbox_ssl/forms/__init__.py` (add to the `.assignments` import
and `__all__`):

```python
    CertificateBulkAssignForm,
```

- [ ] **Step 4: Run the form test to verify it passes**

```bash
docker cp tests/. netbox-ssl-netbox-1:/tmp/plugin_tests/ \
  && docker exec netbox-ssl-netbox-1 /opt/netbox/venv/bin/python -m pytest /tmp/plugin_tests/test_assign_targets_view.py -v
```
Expected: PASS (1 passed).

- [ ] **Step 5: Add the view**

Append to `netbox_ssl/views/assignments.py`:

```python
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.contenttypes.models import ContentType
from django.shortcuts import get_object_or_404, redirect, render
from django.views import View

from dcim.models import Device
from ipam.models import Service
from virtualization.models import VirtualMachine

from ..forms import CertificateBulkAssignForm
from ..models import Certificate
from ..utils.assignments import AssignmentError, assign_certificate_to_targets


class CertificateAssignTargetsView(LoginRequiredMixin, View):
    """Assign one certificate to many Devices/VMs/Services from its detail page."""

    template_name = "netbox_ssl/certificate_assign_targets.html"

    def _get_certificate(self, request, pk):
        return get_object_or_404(Certificate.objects.restrict(request.user, "view"), pk=pk)

    def get(self, request, pk):
        certificate = self._get_certificate(request, pk)
        return render(request, self.template_name, {"object": certificate, "form": CertificateBulkAssignForm()})

    def post(self, request, pk):
        certificate = self._get_certificate(request, pk)
        if not request.user.has_perm("netbox_ssl.add_certificateassignment"):
            messages.error(request, "You do not have permission to assign certificates.")
            return redirect(certificate.get_absolute_url())

        form = CertificateBulkAssignForm(request.POST)
        if not form.is_valid():
            return render(request, self.template_name, {"object": certificate, "form": form})

        targets: list[tuple[ContentType, int]] = []
        for device in form.cleaned_data["devices"]:
            targets.append((ContentType.objects.get_for_model(Device), device.pk))
        for vm in form.cleaned_data["virtual_machines"]:
            targets.append((ContentType.objects.get_for_model(VirtualMachine), vm.pk))
        for service in form.cleaned_data["services"]:
            targets.append((ContentType.objects.get_for_model(Service), service.pk))

        try:
            result = assign_certificate_to_targets(
                certificate, targets, is_primary=form.cleaned_data["is_primary"]
            )
        except AssignmentError as exc:
            messages.error(request, str(exc))
            return redirect(certificate.get_absolute_url())

        messages.success(request, f"Assigned {result.created}, skipped {result.skipped} already assigned.")
        return redirect(certificate.get_absolute_url())
```

Export it from `netbox_ssl/views/__init__.py` — add to the `.assignments`
import block and to `__all__`:

```python
from .assignments import (
    CertificateAssignmentBulkDeleteView,
    CertificateAssignmentDeleteView,
    CertificateAssignmentEditView,
    CertificateAssignmentListView,
    CertificateAssignmentView,
    CertificateAssignTargetsView,
)
```
```python
    "CertificateAssignTargetsView",
```

- [ ] **Step 6: Add the URL**

In `netbox_ssl/urls.py`, add after the `certificate_contacts` path (line ~81):

```python
    path(
        "certificates/<int:pk>/assign-targets/",
        views.CertificateAssignTargetsView.as_view(),
        name="certificate_assign_targets",
    ),
```

- [ ] **Step 7: Add the form template**

Create `netbox_ssl/templates/netbox_ssl/certificate_assign_targets.html`:

```html
{% extends 'generic/_base.html' %}
{% load form_helpers %}
{% block title %}Assign {{ object }} to objects{% endblock %}
{% block content %}
<form action="" method="post">
  {% csrf_token %}
  <div class="card">
    <h2 class="card-header">Assign certificate to objects</h2>
    <div class="card-body">
      <p class="text-muted">
        Assign <strong>{{ object }}</strong> to one or more Devices, Virtual
        Machines, or Services. Objects already assigned are skipped.
      </p>
      {% render_form form %}
    </div>
  </div>
  <div class="text-end my-3">
    <a href="{{ object.get_absolute_url }}" class="btn btn-outline-secondary">Cancel</a>
    <button type="submit" class="btn btn-primary">Assign</button>
  </div>
</form>
{% endblock %}
```

- [ ] **Step 8: Add the detail-page button**

In `netbox_ssl/templates/netbox_ssl/certificate.html`, locate the Renew button
block (the `<a … class="btn btn-warning">` near line ~293) and add this button
beside it so the entry point is always visible (not hidden behind the
conditionally-rendered Assignments tab):

```html
{% if perms.netbox_ssl.add_certificateassignment %}
  <a href="{% url 'plugins:netbox_ssl:certificate_assign_targets' pk=object.pk %}" class="btn btn-primary">
    <i class="mdi mdi-link-plus"></i> Assign to objects
  </a>
{% endif %}
```

- [ ] **Step 9: Add the view tests**

Append to `tests/test_assign_targets_view.py`:

```python
@pytest.mark.django_db
class TestCertificateAssignTargetsView:
    def _make_cert(self):
        from netbox_ssl.models import Certificate

        return Certificate.objects.create(
            common_name="*.example.com",
            serial_number="02:BB",
            issuer="Test CA",
            valid_from="2026-01-01T00:00:00Z",
            valid_to="2027-01-01T00:00:00Z",
        )

    def test_get_renders_form(self, client, django_user_model):
        user = django_user_model.objects.create_user("viewer", password="x", is_superuser=True)
        client.force_login(user)
        cert = self._make_cert()
        url = f"/plugins/ssl/certificates/{cert.pk}/assign-targets/"
        resp = client.get(url)
        assert resp.status_code == 200
        assert b"Assign certificate to objects" in resp.content

    def test_post_creates_assignment_and_redirects(self, client, django_user_model):
        from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site
        from netbox_ssl.models import CertificateAssignment

        user = django_user_model.objects.create_user("admin2", password="x", is_superuser=True)
        client.force_login(user)
        cert = self._make_cert()
        site = Site.objects.create(name="s1", slug="s1")
        mfr = Manufacturer.objects.create(name="m1", slug="m1")
        dtype = DeviceType.objects.create(manufacturer=mfr, model="dt1", slug="dt1")
        role = DeviceRole.objects.create(name="r1", slug="r1")
        device = Device.objects.create(name="web01", site=site, device_type=dtype, role=role)

        url = f"/plugins/ssl/certificates/{cert.pk}/assign-targets/"
        resp = client.post(url, {"devices": [device.pk]})
        assert resp.status_code == 302
        assert CertificateAssignment.objects.filter(certificate=cert).count() == 1
```

- [ ] **Step 10: Run the view tests**

```bash
docker cp tests/. netbox-ssl-netbox-1:/tmp/plugin_tests/ \
  && docker exec netbox-ssl-netbox-1 /opt/netbox/venv/bin/python -m pytest /tmp/plugin_tests/test_assign_targets_view.py -v
```
Expected: PASS (3 passed).

- [ ] **Step 11: Restart container, smoke-test the UI**

Template/URL changes need a worker restart (Django template cache in prod mode):

```bash
docker-compose restart netbox netbox-worker
```
Then load `http://localhost:8000/plugins/ssl/certificates/<pk>/` and confirm the
"Assign to objects" button appears and opens the form; submit a selection and
confirm the success message ("Assigned X, skipped Y already assigned").

- [ ] **Step 12: Update the changelog**

Add (or extend) the `## [Unreleased]` section at the top of `CHANGELOG.md`:

```markdown
## [Unreleased]

### Added

- **Assign one certificate to many objects** ([#148](https://github.com/ctrl-alt-automate/netbox-ssl/issues/148)):
  a wildcard or shared certificate can now be assigned to multiple Devices,
  Virtual Machines, and Services in a single action — via an "Assign to objects"
  button on the certificate detail page, or the new
  `POST /api/plugins/ssl/certificates/{id}/assign-targets` REST action. Targets
  already assigned are silently skipped; the result reports how many were
  assigned and how many were skipped. No database migration.
```

- [ ] **Step 13: Lint and commit**

```bash
ruff check netbox_ssl/forms/assignments.py netbox_ssl/views/assignments.py tests/test_assign_targets_view.py
ruff format --check netbox_ssl/forms/assignments.py netbox_ssl/views/assignments.py tests/test_assign_targets_view.py
git add netbox_ssl/forms/ netbox_ssl/views/ netbox_ssl/urls.py netbox_ssl/templates/ tests/test_assign_targets_view.py CHANGELOG.md
git commit -m "feat: add cert-centric multi-object assignment UI (#148)"
```

---

## Final verification

- [ ] **Run the full new test set**

```bash
docker cp tests/. netbox-ssl-netbox-1:/tmp/plugin_tests/ \
  && docker exec netbox-ssl-netbox-1 /opt/netbox/venv/bin/python -m pytest \
       /tmp/plugin_tests/test_assignments_service.py \
       /tmp/plugin_tests/test_assign_targets_view.py \
       /tmp/plugin_tests/test_api_endpoints.py -k "TestAssignTargetsAPI or Assign" -v
```
Expected: all green.

- [ ] **Django system checks**

```bash
docker exec netbox-ssl-netbox-1 python /opt/netbox/netbox/manage.py check --tag netbox_ssl
```
Expected: no new issues.

- [ ] **Open PR to `dev`** with body containing `Closes #148`, crediting @mkarel.

## Self-review (completed during planning)

- **Spec coverage:** shared service (Task 1) ✓; REST `assign-targets` + `is_primary` default False + batch cap + idempotent skip (Task 2) ✓; cert-centric UI form with three multi-selects + `is_primary` checkbox + detail button + Assignments redirect (Task 3) ✓; security rules — `LoginRequiredMixin`, `.restrict()`, perm gate, generic DB error (Tasks 1–3) ✓; testing plan service/API/form-view ✓; no migration ✓.
- **Placeholders:** none — every code step carries complete code; fixture-reuse notes point at concrete existing helpers.
- **Type consistency:** `assign_certificate_to_targets(certificate, targets, *, is_primary=False) -> AssignResult` and `AssignResult(created, skipped, created_targets, skipped_targets)` are used identically across Tasks 1–3; `AssignTargetsSerializer` request shape matches the API action's parsing; form field names (`devices`, `virtual_machines`, `services`, `is_primary`) match the view's `cleaned_data` access and the test payloads; URL name `certificate_assign_targets` matches the template `{% url %}` and the view tests.
