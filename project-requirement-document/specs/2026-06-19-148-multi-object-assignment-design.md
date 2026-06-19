# Design: Assign one certificate to multiple objects (#148)

- **Issue:** [#148](https://github.com/ctrl-alt-automate/netbox-ssl/issues/148) — "Assign Certificates to Multiple Devices, Virtual Machines, Services" (reported by @mkarel)
- **Date:** 2026-06-19
- **Status:** Approved — ready for implementation plan
- **Author:** maintainer + Claude (brainstorming session)

## 1. Problem

An operator uses a single (often **wildcard**) certificate across many places —
`hr.example.com`, `it.example.com`, dozens of Services on multiple Devices/VMs —
and wants to record *every* place that certificate is used, so the inventory
answers "where is this cert deployed?".

Today the certificate ↔ object relationship already supports this: a
`CertificateAssignment` is a generic M2M row, and one certificate may be
assigned to many objects. The gap is purely in the **web UI**: the
`CertificateAssignmentForm` assigns a certificate to exactly **one** target
(Service *or* Device *or* VM) per submit, so recording a wildcard across 30
services means 30 separate round-trips.

This is a passive-administration (inventory/monitoring) feature — fully in scope
for the plugin's charter.

## 2. Goals / Non-goals

**Goals**

- Assign **one** certificate to **many** objects (Devices, VMs, Services) in a
  single action, from the certificate's own detail page.
- Expose the same capability via the REST API for automation.
- Be idempotent: re-running with overlapping targets must not error.

**Non-goals (YAGNI)**

- Object-centric bulk direction ("from a Device list, assign a cert to many
  devices"). Deferred; the inverse `bulk-assign` API (many certs → one object)
  already covers part of that space.
- Folding multi-target selection into the existing single-assignment
  add/edit form. The single form stays as-is.
- Anything from #149 (website-centric monitoring) — scoped separately.

## 3. Background: what already exists

| Component | Direction | Notes |
|-----------|-----------|-------|
| `CertificateAssignmentForm` (`forms/assignments.py`) | one cert → **one** object | `DynamicModelChoiceField` for device/vm/service; auto-derives content type in `save()`. |
| `bulk-assign` API action (`api/views.py:979`, `detail=False`) | **many certs → one object** | `certificate_ids: [...]` + single `assigned_object`. Idempotent: skips duplicates, returns `created`/`skipped`. **This is the inverse of what #148 needs.** |
| `CertificateAssignment` model (`models/assignments.py`) | — | `UniqueConstraint(certificate, assigned_object_type, assigned_object_id)`. `save()`/`delete()` already fire lifecycle events and touch the parent cert's `last_updated`. Fields: `is_primary`, `notes`, `tags`. |

The data model needs **no migration**. The work is a new "one cert → many
objects" path, surfaced in both the API and the UI, built on a shared service.

## 4. Approach (decided)

A single **shared service function** is the source of truth; the REST API action
and the UI view are thin adapters over it. This avoids duplicating the
skip-duplicates / validate / atomic-create logic in two places (the lesson from
the existing `bulk_assign` action, whose logic lives inline in the viewset).

```
            ┌──────────────────────┐
 UI form ──►│ assign_certificate_  │
            │   to_targets(...)    │──► CertificateAssignment.create() ×N
 API     ──►│  (shared service)    │     (skip existing, atomic)
            └──────────────────────┘
                     │
                     ▼
            AssignResult(created, skipped, …)
```

### 4.1 Shared service — `netbox_ssl/utils/assignments.py` (new module)

```python
@dataclass(frozen=True)
class AssignResult:
    created: int
    skipped: int               # already-assigned targets, silently skipped
    created_targets: tuple[str, ...]
    skipped_targets: tuple[str, ...]

def assign_certificate_to_targets(
    certificate: "Certificate",
    targets: "Sequence[tuple[ContentType, int]]",
    *,
    is_primary: bool = False,
    actor: str | None = None,
) -> AssignResult: ...
```

- Validates each target's content type against the allowlist
  (`dcim.device`, `dcim.service`, `virtualization.virtualmachine`) and that the
  object exists.
- Wraps creation in `transaction.atomic()`. For each target: if a matching
  `CertificateAssignment` already exists → `skipped += 1`; else create it →
  `created += 1`. Per-target existence check mirrors `bulk_assign`.
- Catches `IntegrityError`/`DatabaseError`, logs internally, raises a domain
  error with a generic message (v0.7.5 rule 5).
- Creating the row triggers the model's existing lifecycle-event + `last_updated`
  side effects automatically — no duplication here.

### 4.2 REST API action — `CertificateViewSet`

- `@action(detail=True, methods=["post"], url_path="assign-targets")` →
  `POST /api/plugins/ssl/certificates/{id}/assign-targets`. Mirrors the existing
  `detail=True` actions (`validate-chain`, `compliance-check`, `lifecycle`).
- Permission: `_check_bulk_perm(request, "netbox_ssl.add_certificateassignment")`
  (the same helper `bulk_assign` uses).
- Certificate fetched via `.restrict(request.user, "view")`.
- New `AssignTargetsSerializer`:
  ```json
  {
    "targets": [
      {"object_type": "dcim.device", "object_id": 42},
      {"object_type": "dcim.service", "object_id": 7}
    ],
    "is_primary": false
  }
  ```
  `is_primary` defaults to **false**. Batch size capped at
  `bulk_assign_max_batch_size` (existing setting, default 100).
- Response: `{ "assigned": <int>, "skipped": <int>, "detail": "..." }`,
  HTTP 200.

### 4.3 UI form + view

- **Form** `CertificateBulkAssignForm` (`forms/assignments.py`): three
  `DynamicModelMultipleChoiceField`s — `devices`, `virtual_machines`,
  `services` (all `required=False`) — plus an `is_primary` `BooleanField`
  (`required=False`, default **unchecked**). `clean()` rejects an empty
  selection ("Select at least one Device, Virtual Machine, or Service.").
- **View** `CertificateAssignTargetsView(LoginRequiredMixin, View)` at
  `certificates/<int:pk>/assign-targets/` (follows the existing
  `certificates/<int:pk>/<action>/` URL convention):
  - Fetches the certificate via `.restrict(request.user, "view")`.
  - GET → renders the form. POST → builds `(ContentType, id)` target tuples
    from the three multi-selects and calls `assign_certificate_to_targets()`.
  - `messages.success("Assigned {created}, skipped {skipped} already assigned")`,
    then redirects to the certificate's **Assignments** tab.
  - Security per the v0.7.5 rules: `LoginRequiredMixin` first base class,
    `.restrict()` on every queryset, permission check before the write.
- **Entry point:** an "Assign to objects" button on the **Assignments** tab of
  the certificate detail page.

## 5. Data flow

```
UI form submit / API POST
  └─► serializer.is_valid() / form.clean()      (allowlist + non-empty)
        └─► assign_certificate_to_targets(cert, targets, is_primary=…)
              └─► atomic: for each target → skip-if-exists | create
                    └─► CertificateAssignment.save()  (lifecycle event + touch)
              └─► AssignResult(created, skipped, …)
        └─► UI: success message + redirect to Assignments tab
            API: 200 {assigned, skipped, detail}
```

## 6. Error handling

| Condition | Behaviour |
|-----------|-----------|
| Empty selection | Validation error (form + serializer). |
| Target already assigned | **Not** an error — silently skipped, counted in `skipped`, reported in the summary. |
| Object does not exist / disallowed content type | Validation error naming the field. |
| Batch exceeds `bulk_assign_max_batch_size` | Validation error (as `bulk_assign`). |
| `IntegrityError` / `DatabaseError` | Caught, logged internally, generic message returned (v0.7.5 rule 5). |
| User lacks `add_certificateassignment` | 403 (API) / permission-gated button + view (UI). |

## 7. Security

Follows the project security rules (v0.7.5):

- `LoginRequiredMixin` as the first base class on the custom view.
- `.restrict(request.user, "view")` on the certificate lookup;
  `add_certificateassignment` permission checked before any write.
- Content-type allowlist (`dcim.device`, `dcim.service`,
  `virtualization.virtualmachine`) — no arbitrary GenericForeignKey targets.
- Generic DB-error messages; `str(e)` only logged internally.

## 8. Testing plan (TDD)

Following the project conventions (`find_spec("netbox")` guard,
`@pytest.mark.django_db` on DB-touching tests, marker registered in
`pytest.ini`, host unit lane runs `-p no:django`):

- **Service** (`tests/test_assignments_service.py`, new):
  creates N assignments; skips duplicates (idempotent re-run); mixed
  Device/VM/Service targets in one call; `is_primary` propagation
  (true *and* false); empty target list → error; batch over cap → error;
  disallowed content type → error.
- **API** (`tests/test_api_endpoints.py`): `assign-targets` returns correct
  `assigned`/`skipped` counts; denied without `add_certificateassignment`;
  `.restrict()` enforced (cert not visible → 404/empty); batch cap enforced.
- **Form/View** (`tests/test_*` per existing layout): empty selection invalid;
  success message reports counts; redirect targets the Assignments tab;
  unauthenticated access blocked.

Target: keep the package's unit-coverage gate (70%) green; new service is
fully unit-tested.

## 9. Files touched

| File | Change |
|------|--------|
| `netbox_ssl/utils/assignments.py` | **new** — `AssignResult` + `assign_certificate_to_targets()` |
| `netbox_ssl/api/serializers/certificates.py` | **new** `AssignTargetsSerializer` |
| `netbox_ssl/api/serializers/__init__.py` | export the serializer |
| `netbox_ssl/api/views.py` | new `assign-targets` `detail=True` action |
| `netbox_ssl/forms/assignments.py` | **new** `CertificateBulkAssignForm` |
| `netbox_ssl/views/assignments.py` | **new** `CertificateAssignTargetsView` (co-located with the other assignment views) |
| `netbox_ssl/urls.py` | new `certificates/<int:pk>/assign-targets/` route |
| `netbox_ssl/templates/netbox_ssl/certificate.html` (Assignments tab) | "Assign to objects" button |
| `netbox_ssl/templates/netbox_ssl/certificate_assign_targets.html` | **new** form template for the assign view |
| `tests/…` | service / API / form-view tests |
| `CHANGELOG.md` | `Unreleased` → Added entry |

No database migration.

## 10. Open questions

None blocking. The detail template is confirmed as
`templates/netbox_ssl/certificate.html` (it already renders the Assignments
tab); during implementation, locate the exact tab block so the "Assign to
objects" button lands inside it.

## 11. References

- Inverse precedent: `bulk_assign` action — `netbox_ssl/api/views.py:979`.
- Model: `netbox_ssl/models/assignments.py` (unique constraint, lifecycle hooks).
- Single-assignment form pattern: `netbox_ssl/forms/assignments.py`.
- Security rules: `CLAUDE.md` §"Security Rules (v0.7.5)".
