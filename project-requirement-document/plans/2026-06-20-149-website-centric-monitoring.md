# Website-Centric Certificate Monitoring (#149) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Track the certificate each monitored website (URL) presents over time — with a re-poll script, rotation history, per-endpoint events, and a website-centric view — reusing #106's TLS scraper and the v0.6 event machinery.

**Architecture:** A new `MonitoredEndpoint` model points to the `Certificate` it currently presents; a `MonitoredEndpointCertificate` table records rotation history. A shared `scrape_and_import` service (extracted from #106's inline `_process_row`) is reused by both #106 and a new `poll_endpoint` service. A NetBox-scheduled Script polls all endpoints. Endpoint events fire through the same `last_updated`-touch mechanism as certificate events.

**Tech Stack:** Django, NetBox plugin framework (`NetBoxModel`, generic views, `Script`), Python `ssl`/`socket` (via the existing `tls_scraper`), pytest (`@pytest.mark.django_db`).

## Global Constraints

- **NetBox compatibility:** 4.4–4.6; **Python:** 3.10–3.12.
- **Spec:** `project-requirement-document/specs/2026-06-20-149-website-centric-monitoring-design.md`. **Target release:** v1.3.
- **One additive migration** (two new models); **no changes to existing models** (so no data migration). Generate via real `makemigrations` (NetBox container needs `DEVELOPER=True`); grep the new migration for `custom_field_data` + `tags` on the `NetBoxModel` model.
- **Reuse #106's security model unchanged:** all scraping via `tls_scraper.scrape_tls_certificate` (HTTPS-only, connect to the pre-validated IP — never re-resolve, timeout/size caps); URL validated via `url_validation.validate_https_url(url, cidr_allowlist=...)` before every scrape; private/loopback blocked unless allowlisted via `PLUGINS_CONFIG["netbox_ssl"]["url_import_private_cidr_allowlist"]`; self-signed/untrusted never auto-trusted (recorded `status="untrusted"`).
- **#106 behavior must be unchanged** after the `scrape_and_import` extraction (parity tests required).
- **Security v0.7.5:** every custom view uses `LoginRequiredMixin` first + `.restrict()`; writes perm-gated; DB/scrape errors logged internally (`last_error`), generic messages surfaced.
- **Endpoint status values:** `pending` / `ok` / `unreachable` / `untrusted` only. Rotation is an event + a history row, never a status — a reachable, trusted endpoint stays `ok` right after rotating.
- **Style:** PEP 8, type annotations, black/isort/ruff clean.

## Test Execution

Tests are `@pytest.mark.django_db` and run **inside the running NetBox container** `netbox-ssl-netbox-1` (pytest + pytest-django installed). Copy `tests/` **and** `pytest.ini` to `/tmp/plugin_tests/` before each run (`pytest.ini` supplies `DJANGO_SETTINGS_MODULE=netbox.settings`). Canonical command (per-step `docker cp tests/...` lines are shorthand for it):

```bash
docker cp tests/. netbox-ssl-netbox-1:/tmp/plugin_tests/ \
  && docker cp pytest.ini netbox-ssl-netbox-1:/tmp/plugin_tests/pytest.ini \
  && docker exec netbox-ssl-netbox-1 /opt/netbox/venv/bin/python -m pytest /tmp/plugin_tests/<FILE> -v --tb=short
```
~90s per run (NetBox migration build for the test DB) — normal, be patient. All scraping is **mocked** in tests (no real network): patch `netbox_ssl.utils.url_cert_import.scrape_tls_certificate` (and `validate_https_url`/`socket.getaddrinfo`) to return a fixed PEM or raise `TLSScrapeError`.

## File Structure

| File | Responsibility |
|------|----------------|
| `netbox_ssl/models/monitored_endpoint.py` | **new** — `MonitoredEndpoint`, `MonitoredEndpointCertificate`, `MonitoredEndpointStatusChoices` |
| `netbox_ssl/models/__init__.py` | export the new models + choices |
| `netbox_ssl/migrations/00XX_monitored_endpoint.py` | **new** (generated) — additive |
| `netbox_ssl/utils/url_cert_import.py` | **new** — `ImportOutcome` + `scrape_and_import()` (extracted from #106) |
| `netbox_ssl/views/url_import.py` | refactor `_process_row` to call `scrape_and_import` (behavior unchanged) |
| `netbox_ssl/utils/endpoint_monitor.py` | **new** — `PollResult` + `poll_endpoint()` |
| `netbox_ssl/utils/events.py` | add `EVENT_ENDPOINT_*` + `build_endpoint_event_payload` + `fire_endpoint_event` |
| `netbox_ssl/scripts/endpoint_monitor.py` | **new** — `MonitoredEndpointPoll(Script)` |
| `netbox_ssl/tables/monitored_endpoints.py`, `filtersets/`, `forms/`, `views/monitored_endpoints.py` | **new** CRUD (mirror `ExternalSource`) |
| `netbox_ssl/urls.py`, `navigation.py` | register endpoint routes + nav |
| `netbox_ssl/templates/netbox_ssl/monitoredendpoint.html` | endpoint detail incl. rotation-history tab |
| `netbox_ssl/templates/netbox_ssl/certificate.html` | new "Monitored Endpoints" tab |
| `netbox_ssl/views/certificates.py` | add monitored-endpoints to the certificate detail context |
| `tests/test_monitored_endpoint_model.py`, `test_url_cert_import.py`, `test_endpoint_monitor.py`, `test_endpoint_poll_script.py`, `test_monitored_endpoint_views.py` | **new** tests |
| `CHANGELOG.md` | `Unreleased` → Added |

**Out of scope (YAGNI, not in spec):** REST API / GraphQL for `MonitoredEndpoint` (file a follow-up if wanted), per-endpoint scheduling, IPv6, STARTTLS.

---

## Task 1: Models + migration

**Files:**
- Create: `netbox_ssl/models/monitored_endpoint.py`
- Modify: `netbox_ssl/models/__init__.py`
- Create (generated): `netbox_ssl/migrations/00XX_monitored_endpoint.py`
- Test: `tests/test_monitored_endpoint_model.py`

**Interfaces:**
- Produces:
  - `MonitoredEndpointStatusChoices` (ChoiceSet) with `STATUS_PENDING="pending"`, `STATUS_OK="ok"`, `STATUS_UNREACHABLE="unreachable"`, `STATUS_UNTRUSTED="untrusted"`.
  - `MonitoredEndpoint(NetBoxModel)` fields: `name` (CharField), `url` (CharField), `sni` (CharField, blank), `certificate` (FK→Certificate, null, `SET_NULL`, related_name `monitored_endpoints`), `assigned_object_type`/`assigned_object_id`/`assigned_object` (GenericFK, null, allowlist device/virtualmachine/service), `tenant` (FK→tenancy.Tenant, null, `SET_NULL`), `status` (CharField, choices, default `pending`), `last_checked`/`last_seen` (DateTimeField, null), `last_error` (TextField, blank). `get_absolute_url()`. `@property days_remaining` → `self.certificate.days_remaining if self.certificate else None`.
  - `MonitoredEndpointCertificate(models.Model)` fields: `endpoint` (FK, CASCADE, related_name `cert_history`), `certificate` (FK→Certificate, CASCADE), `first_seen`/`last_seen` (DateTimeField). `UniqueConstraint(endpoint, certificate)`, `ordering = ["-last_seen"]`.

- [ ] **Step 1: Write the failing model test**

Create `tests/test_monitored_endpoint_model.py`:

```python
"""Unit tests for the MonitoredEndpoint models."""

import uuid
import datetime
import pytest
from django.utils import timezone


def _make_cert(serial=None):
    from netbox_ssl.models import Certificate

    uid = uuid.uuid4().hex[:8]
    return Certificate.objects.create(
        common_name=f"{uid}.example.com",
        serial_number=serial or f"SER:{uid}",
        issuer="Test CA",
        valid_from=timezone.now(),
        valid_to=timezone.now() + datetime.timedelta(days=365),
        fingerprint_sha256=":".join([f"{(i % 256):02X}" for i in range(32)]),
        algorithm="RSA",
    )


@pytest.mark.django_db
class TestMonitoredEndpoint:
    def test_create_and_link_certificate(self):
        from netbox_ssl.models import MonitoredEndpoint, MonitoredEndpointStatusChoices

        cert = _make_cert()
        ep = MonitoredEndpoint.objects.create(
            name="HR portal", url="https://hr.example.com:443", certificate=cert
        )
        assert ep.status == MonitoredEndpointStatusChoices.STATUS_PENDING
        assert ep.certificate == cert
        assert ep.days_remaining == cert.days_remaining

    def test_certificate_set_null_on_delete(self):
        from netbox_ssl.models import MonitoredEndpoint

        cert = _make_cert()
        ep = MonitoredEndpoint.objects.create(name="x", url="https://x.example.com", certificate=cert)
        cert.delete()
        ep.refresh_from_db()
        assert ep.certificate is None
```

- [ ] **Step 2: Run to verify it fails**

```bash
docker cp tests/. netbox-ssl-netbox-1:/tmp/plugin_tests/ \
  && docker cp pytest.ini netbox-ssl-netbox-1:/tmp/plugin_tests/pytest.ini \
  && docker exec netbox-ssl-netbox-1 /opt/netbox/venv/bin/python -m pytest /tmp/plugin_tests/test_monitored_endpoint_model.py -v --tb=short
```
Expected: FAIL — `ImportError: cannot import name 'MonitoredEndpoint'`.

- [ ] **Step 3: Write the models**

Create `netbox_ssl/models/monitored_endpoint.py`:

```python
"""Models for website-centric certificate monitoring (#149)."""

from django.contrib.contenttypes.fields import GenericForeignKey
from django.db import models
from django.urls import reverse
from netbox.models import NetBoxModel
from utilities.choices import ChoiceSet


class MonitoredEndpointStatusChoices(ChoiceSet):
    STATUS_PENDING = "pending"
    STATUS_OK = "ok"
    STATUS_UNREACHABLE = "unreachable"
    STATUS_UNTRUSTED = "untrusted"

    CHOICES = [
        (STATUS_PENDING, "Pending", "gray"),
        (STATUS_OK, "OK", "green"),
        (STATUS_UNREACHABLE, "Unreachable", "red"),
        (STATUS_UNTRUSTED, "Untrusted", "orange"),
    ]


class MonitoredEndpoint(NetBoxModel):
    """A monitored website/URL whose presented certificate is tracked over time."""

    name = models.CharField(max_length=200, help_text="Human label, e.g. 'HR portal'.")
    url = models.CharField(max_length=500, help_text="https://host:port to monitor.")
    sni = models.CharField(max_length=255, blank=True, help_text="Optional SNI override (defaults to the URL host).")
    certificate = models.ForeignKey(
        to="netbox_ssl.Certificate",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="monitored_endpoints",
        help_text="The certificate this endpoint currently presents.",
    )
    assigned_object_type = models.ForeignKey(
        to="contenttypes.ContentType",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        limit_choices_to={"model__in": ["service", "device", "virtualmachine"]},
    )
    assigned_object_id = models.PositiveBigIntegerField(null=True, blank=True)
    assigned_object = GenericForeignKey(ct_field="assigned_object_type", fk_field="assigned_object_id")
    tenant = models.ForeignKey(
        to="tenancy.Tenant", on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    status = models.CharField(
        max_length=20,
        choices=MonitoredEndpointStatusChoices,
        default=MonitoredEndpointStatusChoices.STATUS_PENDING,
    )
    last_checked = models.DateTimeField(null=True, blank=True)
    last_seen = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(blank=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("plugins:netbox_ssl:monitoredendpoint", args=[self.pk])

    @property
    def days_remaining(self):
        return self.certificate.days_remaining if self.certificate else None


class MonitoredEndpointCertificate(models.Model):
    """Rotation history: which certificate an endpoint presented, and when."""

    endpoint = models.ForeignKey(
        to=MonitoredEndpoint, on_delete=models.CASCADE, related_name="cert_history"
    )
    certificate = models.ForeignKey(to="netbox_ssl.Certificate", on_delete=models.CASCADE)
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()

    class Meta:
        ordering = ["-last_seen"]
        constraints = [
            models.UniqueConstraint(fields=["endpoint", "certificate"], name="unique_endpoint_certificate"),
        ]

    def __str__(self):
        return f"{self.endpoint} → {self.certificate}"
```

Add to `netbox_ssl/models/__init__.py` (mirror the existing import + `__all__` style):

```python
from .monitored_endpoint import (
    MonitoredEndpoint,
    MonitoredEndpointCertificate,
    MonitoredEndpointStatusChoices,
)
```
and add the three names to `__all__`.

- [ ] **Step 4: Generate the migration**

```bash
docker exec -e DEVELOPER=True netbox-ssl-netbox-1 python /opt/netbox/netbox/manage.py makemigrations netbox_ssl -n monitored_endpoint
docker cp netbox-ssl-netbox-1:/opt/netbox/netbox/netbox_ssl/migrations/. netbox_ssl/migrations/
```
Then **grep the new migration** to confirm `custom_field_data` and `tags` fields are present on `MonitoredEndpoint` (it inherits `NetBoxModel`):
```bash
grep -E "custom_field_data|tags" netbox_ssl/migrations/00XX_monitored_endpoint.py
```
Expected: both appear. If absent, the model didn't inherit `NetBoxModel` correctly — fix before continuing.

- [ ] **Step 5: Run model tests (migration applied automatically by pytest-django)**

```bash
docker cp tests/. netbox-ssl-netbox-1:/tmp/plugin_tests/ \
  && docker cp pytest.ini netbox-ssl-netbox-1:/tmp/plugin_tests/pytest.ini \
  && docker exec netbox-ssl-netbox-1 /opt/netbox/venv/bin/python -m pytest /tmp/plugin_tests/test_monitored_endpoint_model.py -v --tb=short
```
Expected: PASS (2 passed).

- [ ] **Step 6: Add history + "which sites share a cert" tests**

Append to `TestMonitoredEndpoint`:

```python
    def test_rotation_history_unique_constraint(self):
        from django.db import IntegrityError
        from netbox_ssl.models import MonitoredEndpoint, MonitoredEndpointCertificate

        cert = _make_cert()
        ep = MonitoredEndpoint.objects.create(name="x", url="https://x.example.com")
        now = timezone.now()
        MonitoredEndpointCertificate.objects.create(endpoint=ep, certificate=cert, first_seen=now, last_seen=now)
        with pytest.raises(IntegrityError):
            MonitoredEndpointCertificate.objects.create(endpoint=ep, certificate=cert, first_seen=now, last_seen=now)

    def test_which_sites_share_a_certificate(self):
        from netbox_ssl.models import MonitoredEndpoint

        cert = _make_cert()
        MonitoredEndpoint.objects.create(name="a", url="https://a.example.com", certificate=cert)
        MonitoredEndpoint.objects.create(name="b", url="https://b.example.com", certificate=cert)
        MonitoredEndpoint.objects.create(name="c", url="https://c.example.com", certificate=_make_cert())
        assert MonitoredEndpoint.objects.filter(certificate=cert).count() == 2
```

- [ ] **Step 7: Run, lint, commit**

```bash
docker cp tests/. netbox-ssl-netbox-1:/tmp/plugin_tests/ && docker cp pytest.ini netbox-ssl-netbox-1:/tmp/plugin_tests/pytest.ini \
  && docker exec netbox-ssl-netbox-1 /opt/netbox/venv/bin/python -m pytest /tmp/plugin_tests/test_monitored_endpoint_model.py -v --tb=short
ruff check netbox_ssl/models/monitored_endpoint.py tests/test_monitored_endpoint_model.py
git add netbox_ssl/models/ netbox_ssl/migrations/ tests/test_monitored_endpoint_model.py
git commit -m "feat: add MonitoredEndpoint + rotation-history models (#149)"
```
Expected: 4 passed; ruff clean.

---

## Task 2: Shared scrape-and-import service (extract from #106)

**Files:**
- Create: `netbox_ssl/utils/url_cert_import.py`
- Modify: `netbox_ssl/views/url_import.py` (`_process_row` calls the service)
- Modify: `netbox_ssl/utils/__init__.py` (export)
- Test: `tests/test_url_cert_import.py`

**Interfaces:**
- Consumes: `scrape_tls_certificate`, `TLSScrapeError` (`utils/tls_scraper.py`); `validate_https_url`, `URLValidationError` (`utils/url_validation.py`); `CertificateParser`, `CertificateParseError`, `detect_issuing_ca` (`utils/parser.py` / utils).
- Produces:
  - `@dataclass(frozen=True) class ImportOutcome` with `certificate` (Certificate), `created` (bool).
  - `scrape_and_import(url: str, host: str, port: int, *, sni: str | None = None, verify_chain: bool = True, allowlist, tenant=None, set_discovered_url: bool = True) -> ImportOutcome`. Raises `URLValidationError`, `TLSScrapeError`, `CertificateParseError`. (Rotation is NOT computed here — it is endpoint-specific and lives in `poll_endpoint`.)

- [ ] **Step 1: Write the failing test** (`tests/test_url_cert_import.py`)

```python
"""Unit tests for the shared scrape-and-import service."""

import uuid
import pytest
from unittest.mock import patch

# A minimal self-signed-ish PEM is not needed: we mock the scraper to return a
# real fixture PEM and let the real parser run. Reuse the project's cert factory.
from tests.cert_factory import generate_self_signed_pem  # noqa: E402


@pytest.mark.django_db
class TestScrapeAndImport:
    def _pem(self):
        return generate_self_signed_pem(common_name=f"{uuid.uuid4().hex[:8]}.example.com")

    @patch("netbox_ssl.utils.url_cert_import.validate_https_url")
    @patch("netbox_ssl.utils.url_cert_import.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("203.0.113.10", 443))])
    @patch("netbox_ssl.utils.url_cert_import.scrape_tls_certificate")
    def test_creates_certificate_on_miss(self, mock_scrape, _gai, _val):
        from netbox_ssl.models import Certificate
        from netbox_ssl.utils.url_cert_import import scrape_and_import

        mock_scrape.return_value = self._pem()
        before = Certificate.objects.count()
        outcome = scrape_and_import("https://a.example.com", "a.example.com", 443, allowlist=[])
        assert outcome.created is True
        assert Certificate.objects.count() == before + 1
        assert outcome.certificate.discovered_via_url == "https://a.example.com"
```

> If `tests/cert_factory.py` lacks `generate_self_signed_pem`, use the existing factory function it does export (check the file) and adapt the call; the goal is a parseable PEM string.

- [ ] **Step 2: Run to verify it fails**

```bash
docker cp tests/. netbox-ssl-netbox-1:/tmp/plugin_tests/ && docker cp pytest.ini netbox-ssl-netbox-1:/tmp/plugin_tests/pytest.ini \
  && docker exec netbox-ssl-netbox-1 /opt/netbox/venv/bin/python -m pytest /tmp/plugin_tests/test_url_cert_import.py -v --tb=short
```
Expected: FAIL — `ModuleNotFoundError: ...url_cert_import`.

- [ ] **Step 3: Write the service** (`netbox_ssl/utils/url_cert_import.py`)

```python
"""Shared 'scrape a URL → parse → import-or-match' service.

Extracted from views/url_import.py so both the #106 URL import and the #149
endpoint poll use one code path. Raises on failure (callers map to their own
outcome shapes); never swallows.
"""

import socket
from dataclasses import dataclass

from django.db import transaction
from django.utils import timezone

from ..models import Certificate, CertificateStatusChoices
from .parser import CertificateParseError, CertificateParser
from .tls_scraper import TLSScrapeError, scrape_tls_certificate
from .url_validation import URLValidationError, validate_https_url
from . import detect_issuing_ca


@dataclass(frozen=True)
class ImportOutcome:
    certificate: "Certificate"
    created: bool


def scrape_and_import(
    url: str,
    host: str,
    port: int,
    *,
    sni: str | None = None,
    verify_chain: bool = True,
    allowlist,
    tenant=None,
    set_discovered_url: bool = True,
) -> ImportOutcome:
    """Validate, scrape, parse, and import-or-match the cert presented at a URL.

    Raises URLValidationError / TLSScrapeError / CertificateParseError.
    """
    validate_https_url(url, cidr_allowlist=allowlist)
    resolved_ip = socket.getaddrinfo(host, port)[0][4][0]
    pem = scrape_tls_certificate(resolved_ip, host, port, sni=sni, verify_chain=verify_chain)
    parsed = CertificateParser.parse(pem)

    existing = Certificate.objects.filter(
        serial_number=parsed.serial_number, issuer=parsed.issuer
    ).first()
    if existing:
        existing.last_seen_at = timezone.now()
        if set_discovered_url and not existing.discovered_via_url:
            existing.discovered_via_url = url
        existing.save(update_fields=["last_seen_at", "discovered_via_url"])
        return ImportOutcome(certificate=existing, created=False)

    with transaction.atomic():
        cert = Certificate.objects.create(
            common_name=parsed.common_name,
            serial_number=parsed.serial_number,
            fingerprint_sha256=parsed.fingerprint_sha256,
            issuer=parsed.issuer,
            issuing_ca=detect_issuing_ca(parsed.issuer),
            valid_from=parsed.valid_from,
            valid_to=parsed.valid_to,
            sans=parsed.sans or [],
            key_size=parsed.key_size,
            algorithm=parsed.algorithm,
            status=CertificateStatusChoices.STATUS_ACTIVE,
            pem_content=parsed.pem_content,
            issuer_chain=parsed.issuer_chain,
            tenant=tenant,
            discovered_via_url=url if set_discovered_url else "",
            last_seen_at=timezone.now(),
        )
        cert.auto_detect_acme(save=True)
    return ImportOutcome(certificate=cert, created=True)
```

> **Circular-import warning:** import `detect_issuing_ca` from its **defining submodule**, NOT from `from . import detect_issuing_ca` — Step 6 adds `url_cert_import` to `utils/__init__.py`, so importing it back from the package `__init__` would be circular. Grep for its definition (`grep -rn "def detect_issuing_ca" netbox_ssl/utils/`) and import from that module directly (e.g. `from .ca_detector import detect_issuing_ca`). Same for `CertificateParser`/`CertificateParseError` — import from `.parser`. The example above uses `from . import detect_issuing_ca`; replace it with the direct submodule path once you confirm it.

- [ ] **Step 4: Run the create test (GREEN)**

```bash
docker cp tests/. netbox-ssl-netbox-1:/tmp/plugin_tests/ && docker cp pytest.ini netbox-ssl-netbox-1:/tmp/plugin_tests/pytest.ini \
  && docker exec netbox-ssl-netbox-1 /opt/netbox/venv/bin/python -m pytest /tmp/plugin_tests/test_url_cert_import.py -v --tb=short
```
Expected: PASS.

- [ ] **Step 5: Add the match (dedup) test**

```python
    @patch("netbox_ssl.utils.url_cert_import.validate_https_url")
    @patch("netbox_ssl.utils.url_cert_import.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("203.0.113.10", 443))])
    @patch("netbox_ssl.utils.url_cert_import.scrape_tls_certificate")
    def test_matches_existing_on_second_call(self, mock_scrape, _gai, _val):
        from netbox_ssl.models import Certificate
        from netbox_ssl.utils.url_cert_import import scrape_and_import

        pem = self._pem()
        mock_scrape.return_value = pem
        first = scrape_and_import("https://a.example.com", "a.example.com", 443, allowlist=[])
        before = Certificate.objects.count()
        second = scrape_and_import("https://a.example.com", "a.example.com", 443, allowlist=[])
        assert second.created is False
        assert second.certificate.pk == first.certificate.pk
        assert Certificate.objects.count() == before
```

- [ ] **Step 6: Refactor `_process_row` to call the service**

In `netbox_ssl/views/url_import.py`, replace the body of `_process_row` (steps 1–6, lines ~157–227) so it calls `scrape_and_import` and maps exceptions to the **existing outcome dict shapes** (do not change the returned keys/values — the result template depends on them):

```python
    def _process_row(self, request, row, allowlist, user_tenants, default_tenant):
        """Validate → scrape → parse → import a single row; return an outcome dict."""
        from ..utils.url_cert_import import scrape_and_import

        label = row["url"]
        tenant = self._resolve_tenant(row.get("tenant"), user_tenants) or default_tenant
        try:
            outcome = scrape_and_import(
                row["url"], row["host"], row["port"],
                sni=row["sni"], verify_chain=row["verify_chain"],
                allowlist=allowlist, tenant=tenant,
            )
        except URLValidationError as exc:
            return {"url": label, "status": "blocked", "detail": str(exc)}
        except TLSScrapeError as exc:
            return {"url": label, "status": "unreachable", "detail": str(exc)}
        except CertificateParseError as exc:
            return {"url": label, "status": "error", "detail": str(exc)}
        except Exception as exc:  # noqa: BLE001 - surface per-row, don't abort the batch
            return {"url": label, "status": "error", "detail": str(exc)}

        if not outcome.created:
            return {"url": label, "status": "matched", "detail": outcome.certificate.common_name, "pk": outcome.certificate.pk}
        status = "imported" if row["verify_chain"] else "imported_untrusted"
        return {"url": label, "status": status, "detail": outcome.certificate.common_name, "pk": outcome.certificate.pk}
```

Leave the surrounding imports in `url_import.py` (they are still referenced by the except clauses). Add `"scrape_and_import"`, `"ImportOutcome"` to `netbox_ssl/utils/__init__.py` exports.

- [ ] **Step 7: #106 parity test**

Add `tests/test_url_cert_import.py::TestProcessRowParity` asserting the refactored view path still returns the documented outcome shapes for matched/imported. If `tests/test_bulk_data_import.py` or an existing URL-import test exercises `_process_row`/`_scan_and_import`, run that file too and confirm it still passes:

```bash
docker cp tests/. netbox-ssl-netbox-1:/tmp/plugin_tests/ && docker cp pytest.ini netbox-ssl-netbox-1:/tmp/plugin_tests/pytest.ini \
  && docker exec netbox-ssl-netbox-1 /opt/netbox/venv/bin/python -m pytest /tmp/plugin_tests/test_url_cert_import.py -v --tb=short
```
Expected: PASS. Then grep for an existing url-import test and run it to confirm unchanged behavior.

- [ ] **Step 8: Lint, commit**

```bash
ruff check netbox_ssl/utils/url_cert_import.py netbox_ssl/views/url_import.py tests/test_url_cert_import.py
git add netbox_ssl/utils/url_cert_import.py netbox_ssl/utils/__init__.py netbox_ssl/views/url_import.py tests/test_url_cert_import.py
git commit -m "refactor: extract shared scrape_and_import service from URL import (#149)"
```

---

## Task 3: Endpoint poll service + endpoint events

**Files:**
- Create: `netbox_ssl/utils/endpoint_monitor.py`
- Modify: `netbox_ssl/utils/events.py` (endpoint event types + helpers)
- Test: `tests/test_endpoint_monitor.py`

**Interfaces:**
- Consumes: `scrape_and_import`, `ImportOutcome` (Task 2); `TLSScrapeError`, `URLValidationError`; `MonitoredEndpoint`, `MonitoredEndpointCertificate`, `MonitoredEndpointStatusChoices` (Task 1).
- Produces:
  - `utils/events.py`: `EVENT_ENDPOINT_UNREACHABLE="endpoint_unreachable"`, `EVENT_ENDPOINT_CERT_ROTATED="endpoint_cert_rotated"`, `EVENT_ENDPOINT_UNTRUSTED_CERT="endpoint_untrusted_cert"`; `build_endpoint_event_payload(endpoint, event_type, extra=None) -> dict`; `fire_endpoint_event(endpoint, event_type, extra=None) -> dict`.
  - `utils/endpoint_monitor.py`: `@dataclass(frozen=True) class PollResult` (`endpoint`, `status: str`, `rotated: bool`, `events_fired: tuple[str, ...]`); `poll_endpoint(endpoint, *, allowlist) -> PollResult`.

- [ ] **Step 1: Write the failing event-helper test** (`tests/test_endpoint_monitor.py`)

```python
"""Unit tests for endpoint events + the poll service."""

import uuid
import datetime
import pytest
from unittest.mock import patch
from django.utils import timezone


def _make_cert(serial=None):
    from netbox_ssl.models import Certificate

    uid = uuid.uuid4().hex[:8]
    return Certificate.objects.create(
        common_name=f"{uid}.example.com", serial_number=serial or f"SER:{uid}",
        issuer="Test CA", valid_from=timezone.now(),
        valid_to=timezone.now() + datetime.timedelta(days=365),
        fingerprint_sha256=":".join([f"{(i % 256):02X}" for i in range(32)]), algorithm="RSA",
    )


@pytest.mark.django_db
class TestEndpointEventPayload:
    def test_payload_has_endpoint_fields(self):
        from netbox_ssl.models import MonitoredEndpoint
        from netbox_ssl.utils.events import EVENT_ENDPOINT_UNREACHABLE, build_endpoint_event_payload

        ep = MonitoredEndpoint.objects.create(name="hr", url="https://hr.example.com")
        payload = build_endpoint_event_payload(ep, EVENT_ENDPOINT_UNREACHABLE)
        assert payload["event_type"] == EVENT_ENDPOINT_UNREACHABLE
        assert payload["endpoint_id"] == ep.pk
        assert payload["url"] == "https://hr.example.com"
```

- [ ] **Step 2: Run to verify it fails**

```bash
docker cp tests/. netbox-ssl-netbox-1:/tmp/plugin_tests/ && docker cp pytest.ini netbox-ssl-netbox-1:/tmp/plugin_tests/pytest.ini \
  && docker exec netbox-ssl-netbox-1 /opt/netbox/venv/bin/python -m pytest /tmp/plugin_tests/test_endpoint_monitor.py -v --tb=short
```
Expected: FAIL — `ImportError: cannot import name 'EVENT_ENDPOINT_UNREACHABLE'`.

- [ ] **Step 3: Add endpoint events to `utils/events.py`**

Append:

```python
EVENT_ENDPOINT_UNREACHABLE = "endpoint_unreachable"
EVENT_ENDPOINT_CERT_ROTATED = "endpoint_cert_rotated"
EVENT_ENDPOINT_UNTRUSTED_CERT = "endpoint_untrusted_cert"


def build_endpoint_event_payload(endpoint: Any, event_type: str, extra: dict | None = None) -> dict:
    """Build a standardized event payload for a monitored-endpoint event."""
    cert = endpoint.certificate
    payload = {
        "event_type": event_type,
        "endpoint_id": endpoint.pk,
        "name": endpoint.name,
        "url": endpoint.url,
        "status": endpoint.status,
        "certificate_id": cert.pk if cert else None,
        "common_name": cert.common_name if cert else None,
        "days_remaining": cert.days_remaining if cert else None,
        "tenant": endpoint.tenant.name if endpoint.tenant else None,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
    }
    if extra:
        payload.update(extra)
    return payload


def fire_endpoint_event(endpoint: Any, event_type: str, extra: dict | None = None) -> dict:
    """Fire a monitored-endpoint event by touching last_updated (same mechanism as certs)."""
    payload = build_endpoint_event_payload(endpoint, event_type, extra=extra)
    try:
        from django.utils import timezone as dj_timezone

        type(endpoint).objects.filter(pk=endpoint.pk).update(last_updated=dj_timezone.now())
    except Exception as e:
        logger.warning("Could not update last_updated for endpoint %s: %s", endpoint.pk, e)
    return payload
```

- [ ] **Step 4: Run the payload test (GREEN)**

```bash
docker cp tests/. netbox-ssl-netbox-1:/tmp/plugin_tests/ && docker cp pytest.ini netbox-ssl-netbox-1:/tmp/plugin_tests/pytest.ini \
  && docker exec netbox-ssl-netbox-1 /opt/netbox/venv/bin/python -m pytest /tmp/plugin_tests/test_endpoint_monitor.py -v --tb=short
```
Expected: PASS.

- [ ] **Step 5: Write the poll-service tests**

```python
@pytest.mark.django_db
class TestPollEndpoint:
    def _ep(self, **kw):
        from netbox_ssl.models import MonitoredEndpoint
        return MonitoredEndpoint.objects.create(name="hr", url="https://hr.example.com:443", **kw)

    @patch("netbox_ssl.utils.endpoint_monitor.scrape_and_import")
    def test_ok_links_cert_and_history(self, mock_import):
        from netbox_ssl.models import MonitoredEndpointCertificate, MonitoredEndpointStatusChoices
        from netbox_ssl.utils.url_cert_import import ImportOutcome
        from netbox_ssl.utils.endpoint_monitor import poll_endpoint

        cert = _make_cert()
        mock_import.return_value = ImportOutcome(certificate=cert, created=True)
        ep = self._ep()
        result = poll_endpoint(ep, allowlist=[])
        ep.refresh_from_db()
        assert result.status == MonitoredEndpointStatusChoices.STATUS_OK
        assert ep.certificate == cert
        assert ep.last_seen is not None
        assert MonitoredEndpointCertificate.objects.filter(endpoint=ep, certificate=cert).count() == 1

    @patch("netbox_ssl.utils.endpoint_monitor.scrape_and_import")
    def test_unreachable_fires_event(self, mock_import):
        from netbox_ssl.utils.tls_scraper import TLSScrapeError
        from netbox_ssl.models import MonitoredEndpointStatusChoices
        from netbox_ssl.utils.events import EVENT_ENDPOINT_UNREACHABLE
        from netbox_ssl.utils.endpoint_monitor import poll_endpoint

        mock_import.side_effect = TLSScrapeError("connection refused")
        ep = self._ep()
        result = poll_endpoint(ep, allowlist=[])
        ep.refresh_from_db()
        assert result.status == MonitoredEndpointStatusChoices.STATUS_UNREACHABLE
        assert EVENT_ENDPOINT_UNREACHABLE in result.events_fired
        assert ep.last_error

    @patch("netbox_ssl.utils.endpoint_monitor.scrape_and_import")
    def test_rotation_fires_event_and_keeps_status_ok(self, mock_import):
        from netbox_ssl.utils.url_cert_import import ImportOutcome
        from netbox_ssl.models import MonitoredEndpointStatusChoices
        from netbox_ssl.utils.events import EVENT_ENDPOINT_CERT_ROTATED
        from netbox_ssl.utils.endpoint_monitor import poll_endpoint

        cert_a, cert_b = _make_cert(), _make_cert()
        ep = self._ep(certificate=cert_a)
        mock_import.return_value = ImportOutcome(certificate=cert_b, created=False)
        result = poll_endpoint(ep, allowlist=[])
        ep.refresh_from_db()
        assert result.rotated is True
        assert ep.certificate == cert_b
        assert result.status == MonitoredEndpointStatusChoices.STATUS_OK
        assert EVENT_ENDPOINT_CERT_ROTATED in result.events_fired

    @patch("netbox_ssl.utils.endpoint_monitor.scrape_and_import")
    def test_untrusted_when_verify_fails_then_succeeds(self, mock_import):
        from netbox_ssl.utils.tls_scraper import TLSScrapeError
        from netbox_ssl.utils.url_cert_import import ImportOutcome
        from netbox_ssl.models import MonitoredEndpointStatusChoices
        from netbox_ssl.utils.events import EVENT_ENDPOINT_UNTRUSTED_CERT
        from netbox_ssl.utils.endpoint_monitor import poll_endpoint

        cert = _make_cert()
        # First (verify_chain=True) raises; second (verify_chain=False) succeeds.
        mock_import.side_effect = [TLSScrapeError("self-signed"), ImportOutcome(certificate=cert, created=True)]
        ep = self._ep()
        result = poll_endpoint(ep, allowlist=[])
        ep.refresh_from_db()
        assert result.status == MonitoredEndpointStatusChoices.STATUS_UNTRUSTED
        assert ep.certificate == cert
        assert EVENT_ENDPOINT_UNTRUSTED_CERT in result.events_fired
```

- [ ] **Step 6: Run to verify they fail**

```bash
docker cp tests/. netbox-ssl-netbox-1:/tmp/plugin_tests/ && docker cp pytest.ini netbox-ssl-netbox-1:/tmp/plugin_tests/pytest.ini \
  && docker exec netbox-ssl-netbox-1 /opt/netbox/venv/bin/python -m pytest /tmp/plugin_tests/test_endpoint_monitor.py::TestPollEndpoint -v --tb=short
```
Expected: FAIL — `ImportError: ...endpoint_monitor`.

- [ ] **Step 7: Write the poll service** (`netbox_ssl/utils/endpoint_monitor.py`)

```python
"""Poll a MonitoredEndpoint: scrape its cert, link it, track rotation, fire events."""

from dataclasses import dataclass
from urllib.parse import urlsplit

from django.db import transaction
from django.utils import timezone

from ..models import MonitoredEndpointCertificate, MonitoredEndpointStatusChoices
from .events import (
    EVENT_ENDPOINT_CERT_ROTATED,
    EVENT_ENDPOINT_UNREACHABLE,
    EVENT_ENDPOINT_UNTRUSTED_CERT,
    fire_endpoint_event,
)
from .tls_scraper import TLSScrapeError
from .url_cert_import import scrape_and_import
from .url_validation import URLValidationError


@dataclass(frozen=True)
class PollResult:
    endpoint: "object"
    status: str
    rotated: bool
    events_fired: tuple[str, ...]


def _host_port(url: str) -> tuple[str, int]:
    parts = urlsplit(url)
    return parts.hostname or "", parts.port or 443


def poll_endpoint(endpoint, *, allowlist) -> PollResult:
    """Scrape the endpoint's current cert and reconcile the endpoint record."""
    host, port = _host_port(endpoint.url)
    sni = endpoint.sni or None
    prev_cert_id = endpoint.certificate_id
    events: list[str] = []
    now = timezone.now()

    def _do(verify):
        return scrape_and_import(
            endpoint.url, host, port, sni=sni, verify_chain=verify,
            allowlist=allowlist, tenant=endpoint.tenant, set_discovered_url=True,
        )

    untrusted = False
    try:
        outcome = _do(True)
    except (TLSScrapeError, URLValidationError):
        try:
            outcome = _do(False)
            untrusted = True
        except (TLSScrapeError, URLValidationError) as exc:
            endpoint.status = MonitoredEndpointStatusChoices.STATUS_UNREACHABLE
            endpoint.last_checked = now
            endpoint.last_error = str(exc)
            endpoint.save(update_fields=["status", "last_checked", "last_error"])
            fire_endpoint_event(endpoint, EVENT_ENDPOINT_UNREACHABLE)
            return PollResult(endpoint, endpoint.status, False, (EVENT_ENDPOINT_UNREACHABLE,))
    except Exception as exc:  # noqa: BLE001 - record + continue (e.g. parse error)
        endpoint.status = MonitoredEndpointStatusChoices.STATUS_UNREACHABLE
        endpoint.last_checked = now
        endpoint.last_error = str(exc)
        endpoint.save(update_fields=["status", "last_checked", "last_error"])
        fire_endpoint_event(endpoint, EVENT_ENDPOINT_UNREACHABLE)
        return PollResult(endpoint, endpoint.status, False, (EVENT_ENDPOINT_UNREACHABLE,))

    cert = outcome.certificate
    rotated = prev_cert_id is not None and prev_cert_id != cert.pk

    with transaction.atomic():
        endpoint.certificate = cert
        endpoint.last_checked = now
        endpoint.last_seen = now
        endpoint.last_error = ""
        endpoint.status = (
            MonitoredEndpointStatusChoices.STATUS_UNTRUSTED
            if untrusted
            else MonitoredEndpointStatusChoices.STATUS_OK
        )
        endpoint.save(update_fields=["certificate", "last_checked", "last_seen", "last_error", "status"])

        hist, created = MonitoredEndpointCertificate.objects.get_or_create(
            endpoint=endpoint, certificate=cert, defaults={"first_seen": now, "last_seen": now}
        )
        if not created:
            hist.last_seen = now
            hist.save(update_fields=["last_seen"])

    if untrusted:
        events.append(EVENT_ENDPOINT_UNTRUSTED_CERT)
        fire_endpoint_event(endpoint, EVENT_ENDPOINT_UNTRUSTED_CERT)
    if rotated:
        events.append(EVENT_ENDPOINT_CERT_ROTATED)
        fire_endpoint_event(endpoint, EVENT_ENDPOINT_CERT_ROTATED, extra={"previous_certificate_id": prev_cert_id})

    return PollResult(endpoint, endpoint.status, rotated, tuple(events))
```

- [ ] **Step 8: Run (GREEN), lint, commit**

```bash
docker cp tests/. netbox-ssl-netbox-1:/tmp/plugin_tests/ && docker cp pytest.ini netbox-ssl-netbox-1:/tmp/plugin_tests/pytest.ini \
  && docker exec netbox-ssl-netbox-1 /opt/netbox/venv/bin/python -m pytest /tmp/plugin_tests/test_endpoint_monitor.py -v --tb=short
ruff check netbox_ssl/utils/endpoint_monitor.py netbox_ssl/utils/events.py tests/test_endpoint_monitor.py
git add netbox_ssl/utils/endpoint_monitor.py netbox_ssl/utils/events.py tests/test_endpoint_monitor.py
git commit -m "feat: add endpoint poll service + endpoint events (#149)"
```
Expected: all poll + payload tests pass; ruff clean.

---

## Task 4: Re-poll NetBox Script

**Files:**
- Create: `netbox_ssl/scripts/endpoint_monitor.py`
- Test: `tests/test_endpoint_poll_script.py`

**Interfaces:**
- Consumes: `poll_endpoint`, `PollResult` (Task 3); `MonitoredEndpoint` (Task 1).
- Produces: `MonitoredEndpointPoll(Script)` whose `run(data, commit)` iterates endpoints (optional tenant filter, `dry_run`), calls `poll_endpoint`, logs a per-status summary, returns a summary string.

- [ ] **Step 1: Write the failing test** (`tests/test_endpoint_poll_script.py`)

> Mirror the structure of the existing `tests/test_expiry_scan.py`. Scripts are instantiated and `run()` called directly with a `data` dict. Mock `poll_endpoint` so no network/poll logic runs here — this test covers the Script's orchestration only.

```python
import uuid
import pytest
from unittest.mock import patch


@pytest.mark.django_db
class TestMonitoredEndpointPollScript:
    def _ep(self):
        from netbox_ssl.models import MonitoredEndpoint
        return MonitoredEndpoint.objects.create(name=f"e{uuid.uuid4().hex[:6]}", url="https://e.example.com")

    @patch("netbox_ssl.scripts.endpoint_monitor.poll_endpoint")
    def test_polls_all_endpoints(self, mock_poll):
        from netbox_ssl.models import MonitoredEndpointStatusChoices
        from netbox_ssl.scripts.endpoint_monitor import MonitoredEndpointPoll
        from netbox_ssl.utils.endpoint_monitor import PollResult

        ep1, ep2 = self._ep(), self._ep()
        mock_poll.side_effect = lambda ep, **kw: PollResult(ep, MonitoredEndpointStatusChoices.STATUS_OK, False, ())
        script = MonitoredEndpointPoll()
        script.run({"tenant": None, "dry_run": False}, commit=True)
        assert mock_poll.call_count == 2
```

- [ ] **Step 2: Run to verify it fails**

```bash
docker cp tests/. netbox-ssl-netbox-1:/tmp/plugin_tests/ && docker cp pytest.ini netbox-ssl-netbox-1:/tmp/plugin_tests/pytest.ini \
  && docker exec netbox-ssl-netbox-1 /opt/netbox/venv/bin/python -m pytest /tmp/plugin_tests/test_endpoint_poll_script.py -v --tb=short
```
Expected: FAIL — `ModuleNotFoundError: ...scripts.endpoint_monitor`.

- [ ] **Step 3: Write the Script** (`netbox_ssl/scripts/endpoint_monitor.py`)

> Mirror `netbox_ssl/scripts/expiry_scan.py` for the `Script`/`ObjectVar`/`BooleanVar` imports, `class Meta`, `get_plugin_setting`, and `log_*` helpers. **`ObjectVar(model=...)` must take the model CLASS, not a string** (see [[netbox-plugin-scripts-loading]], #143).

```python
"""NetBox Script: re-poll all MonitoredEndpoints and reconcile their certs."""

from extras.scripts import BooleanVar, ObjectVar, Script
from tenancy.models import Tenant

from netbox_ssl.models import MonitoredEndpoint, MonitoredEndpointStatusChoices
from netbox_ssl.utils.endpoint_monitor import poll_endpoint


class MonitoredEndpointPoll(Script):
    class Meta:
        name = "Monitored Endpoint Poll"
        description = "Re-scrape each monitored endpoint and update its certificate, status, and history."

    tenant = ObjectVar(model=Tenant, required=False, description="Limit to one tenant.")
    dry_run = BooleanVar(default=False, description="Log actions without saving.")

    def run(self, data, commit):
        from django.conf import settings

        allowlist = settings.PLUGINS_CONFIG.get("netbox_ssl", {}).get("url_import_private_cidr_allowlist", [])
        endpoints = MonitoredEndpoint.objects.all()
        if data.get("tenant"):
            endpoints = endpoints.filter(tenant=data["tenant"])

        counts = {c[0]: 0 for c in MonitoredEndpointStatusChoices.CHOICES}
        rotated = 0
        for endpoint in endpoints:
            if data.get("dry_run"):
                self.log_info(f"[dry-run] would poll {endpoint.name} ({endpoint.url})")
                continue
            result = poll_endpoint(endpoint, allowlist=allowlist)
            counts[result.status] = counts.get(result.status, 0) + 1
            if result.rotated:
                rotated += 1
            self.log_info(f"{endpoint.name}: {result.status}" + (" (rotated)" if result.rotated else ""))

        summary = ", ".join(f"{k}={v}" for k, v in counts.items() if v) + (f", rotated={rotated}" if rotated else "")
        self.log_success(f"Polled {endpoints.count()} endpoint(s): {summary or 'no changes'}")
        return summary
```

- [ ] **Step 4: Run (GREEN), add a dry-run test**

Add a dry-run test asserting `poll_endpoint` is NOT called when `dry_run=True`:

```python
    @patch("netbox_ssl.scripts.endpoint_monitor.poll_endpoint")
    def test_dry_run_does_not_poll(self, mock_poll):
        from netbox_ssl.scripts.endpoint_monitor import MonitoredEndpointPoll
        self._ep()
        MonitoredEndpointPoll().run({"tenant": None, "dry_run": True}, commit=False)
        mock_poll.assert_not_called()
```

```bash
docker cp tests/. netbox-ssl-netbox-1:/tmp/plugin_tests/ && docker cp pytest.ini netbox-ssl-netbox-1:/tmp/plugin_tests/pytest.ini \
  && docker exec netbox-ssl-netbox-1 /opt/netbox/venv/bin/python -m pytest /tmp/plugin_tests/test_endpoint_poll_script.py -v --tb=short
```
Expected: PASS (2 passed).

- [ ] **Step 5: Add the AST/registration guard + lint + commit**

Confirm the new Script passes the existing `tests/test_script_objectvar.py` guard (the AST check that no `ObjectVar(model="string")` exists), then:

```bash
docker exec netbox-ssl-netbox-1 /opt/netbox/venv/bin/python -m pytest /tmp/plugin_tests/test_script_objectvar.py -v --tb=short
ruff check netbox_ssl/scripts/endpoint_monitor.py tests/test_endpoint_poll_script.py
git add netbox_ssl/scripts/endpoint_monitor.py tests/test_endpoint_poll_script.py
git commit -m "feat: add MonitoredEndpointPoll re-poll script (#149)"
```

---

## Task 5: Provisioning — CRUD, bulk CSV, #106 auto-create hook

**Files:**
- Create: `netbox_ssl/forms/monitored_endpoints.py`, `netbox_ssl/tables/monitored_endpoints.py`, `netbox_ssl/filtersets/monitored_endpoints.py`, `netbox_ssl/views/monitored_endpoints.py`
- Modify: the `forms/`, `tables/`, `filtersets/`, `views/` `__init__.py`; `netbox_ssl/urls.py`; `netbox_ssl/navigation.py`
- Modify: `netbox_ssl/utils/url_cert_import.py` is NOT touched; add the auto-create hook in `netbox_ssl/views/url_import.py`
- Test: extend `tests/test_monitored_endpoint_views.py`

**Interfaces:**
- Consumes: `MonitoredEndpoint` (Task 1).
- Produces: list/add/edit/delete/detail URL names `monitoredendpoint_list`, `monitoredendpoint_add`, `monitoredendpoint`, `monitoredendpoint_edit`, `monitoredendpoint_delete`, plus `monitoredendpoint_import` (bulk CSV).

This task is **NetBox CRUD boilerplate** — mirror the existing `ExternalSource` CRUD exactly. For each file, copy the structure from its `ExternalSource` counterpart and swap model/fields:

- [ ] **Step 1: Table** — `netbox_ssl/tables/monitored_endpoints.py`, mirror `tables/external_sources.py`. Columns: `name` (linkified), `url`, `status` (`ChoiceFieldColumn`), `certificate` (linkified), `days_remaining`, `tenant`, `last_checked`. Register in `tables/__init__.py`.

- [ ] **Step 2: FilterSet** — `filtersets/monitored_endpoints.py`, mirror `filtersets/external_sources.py`. Filters: `status` (multiple choice from `MonitoredEndpointStatusChoices`), `certificate_id` (`ModelMultipleChoiceFilter`), `tenant_id`, `q` (search `name`/`url`). Register in `filtersets/__init__.py`.

- [ ] **Step 3: Forms** — `forms/monitored_endpoints.py`, mirror `forms/external_sources.py`: a `MonitoredEndpointForm(NetBoxModelForm)` (fields `name`, `url`, `sni`, `tenant`, `device`/`virtual_machine`/`service` resolving to the GenericFK like `CertificateAssignmentForm` does, `tags`), a `MonitoredEndpointFilterForm`, and a `MonitoredEndpointImportForm` (CSV `TextVar`-style textarea) reusing `utils/url_bulk_parser`. Register in `forms/__init__.py`.

- [ ] **Step 4: Views** — `views/monitored_endpoints.py`, mirror `views/external_sources.py`: `MonitoredEndpointListView`, `MonitoredEndpointView`, `MonitoredEndpointEditView`, `MonitoredEndpointDeleteView`, `MonitoredEndpointBulkDeleteView`, and a `MonitoredEndpointImportView(LoginRequiredMixin, View)` that parses CSV via `url_bulk_parser` and creates endpoints. Register in `views/__init__.py`.

- [ ] **Step 5: URLs + navigation** — add the routes to `urls.py` (mirror the certificate/external-source URL block, names listed in Interfaces above) and a nav item to `navigation.py` (mirror the existing SSL menu group entries). Import the views in `urls.py`.

- [ ] **Step 6: #106 auto-create hook** — in `netbox_ssl/views/url_import.py`, after a row imports successfully in `_process_row` (status `imported`/`imported_untrusted`/`matched`), upsert a `MonitoredEndpoint` for `row["url"]` linked to the resulting cert:

```python
        # #149: keep a MonitoredEndpoint for every imported URL.
        from ..models import MonitoredEndpoint

        MonitoredEndpoint.objects.update_or_create(
            url=row["url"],
            defaults={
                "name": row.get("name") or row["host"],
                "sni": row.get("sni") or "",
                "certificate": outcome.certificate,
                "tenant": tenant,
                "last_seen": timezone.now(),
                "last_checked": timezone.now(),
                "status": MonitoredEndpointStatusChoices.STATUS_OK,
            },
        )
```
Import `MonitoredEndpointStatusChoices` at the top of `url_import.py`.

- [ ] **Step 7: Tests** — `tests/test_monitored_endpoint_views.py`:

```python
import uuid
import pytest


@pytest.mark.django_db
class TestMonitoredEndpointViews:
    def test_list_requires_login(self, client):
        resp = client.get("/plugins/ssl/monitored-endpoints/")
        assert resp.status_code in (302, 403)  # redirected to login

    def test_list_renders_for_superuser(self, client, django_user_model):
        user = django_user_model.objects.create_user("u", password="x", is_superuser=True)
        client.force_login(user)
        from netbox_ssl.models import MonitoredEndpoint
        MonitoredEndpoint.objects.create(name="hr", url="https://hr.example.com")
        resp = client.get("/plugins/ssl/monitored-endpoints/")
        assert resp.status_code == 200
        assert b"hr" in resp.content
```
Plus a test that the #106 auto-create hook upserts an endpoint (patch `scrape_and_import` in `url_import`, drive `_process_row`, assert a `MonitoredEndpoint` exists for the URL).

- [ ] **Step 8: Run, restart, lint, commit**

```bash
docker cp tests/. netbox-ssl-netbox-1:/tmp/plugin_tests/ && docker cp pytest.ini netbox-ssl-netbox-1:/tmp/plugin_tests/pytest.ini \
  && docker exec netbox-ssl-netbox-1 /opt/netbox/venv/bin/python -m pytest /tmp/plugin_tests/test_monitored_endpoint_views.py -v --tb=short
docker-compose restart netbox netbox-worker   # template/url/nav changes
ruff check netbox_ssl/tables/monitored_endpoints.py netbox_ssl/filtersets/monitored_endpoints.py netbox_ssl/forms/monitored_endpoints.py netbox_ssl/views/monitored_endpoints.py netbox_ssl/views/url_import.py
git add netbox_ssl/ tests/test_monitored_endpoint_views.py
git commit -m "feat: add MonitoredEndpoint CRUD, bulk CSV, and #106 auto-create (#149)"
```

---

## Task 6: Website-centric views — endpoint detail rotation tab + certificate reverse tab

**Files:**
- Create: `netbox_ssl/templates/netbox_ssl/monitoredendpoint.html`
- Modify: `netbox_ssl/templates/netbox_ssl/certificate.html`, `netbox_ssl/views/certificates.py`
- Test: extend `tests/test_monitored_endpoint_views.py`

**Interfaces:**
- Consumes: `MonitoredEndpoint`, `MonitoredEndpointCertificate` (Task 1); the detail views (Task 5).

- [ ] **Step 1: Endpoint detail template** — `monitoredendpoint.html`, mirroring `certificateauthority.html`/`externalsource.html`: a details card (url, status badge, linked certificate + `days_remaining`, last_checked/last_seen, assigned object, tenant) and a **Rotation History** tab listing `object.cert_history.all` (certificate link, first_seen, last_seen). The `MonitoredEndpointView` (Task 5) already supplies `object`; `cert_history` is the related manager.

- [ ] **Step 2: Certificate "Monitored Endpoints" tab** — in `views/certificates.py`, find the `CertificateView` (the `generic.ObjectView` for `Certificate`) and add to its detail context (via `get_extra_context`) `monitored_endpoints = instance.monitored_endpoints.restrict(request.user, "view")` and `monitored_endpoints_count`. In `certificate.html`, add a tab `#tab-monitored-endpoints` (mirroring the existing `#tab-assignments` block from #148) that renders the list (name link, url, status badge, days_remaining), shown when `monitored_endpoints` is non-empty.

- [ ] **Step 3: Tests**

```python
    def test_certificate_detail_shows_linked_endpoints(self, client, django_user_model):
        import datetime
        from django.utils import timezone
        from netbox_ssl.models import Certificate, MonitoredEndpoint

        user = django_user_model.objects.create_user("u2", password="x", is_superuser=True)
        client.force_login(user)
        uid = uuid.uuid4().hex[:8]
        cert = Certificate.objects.create(
            common_name=f"{uid}.example.com", serial_number=f"S:{uid}", issuer="CA",
            valid_from=timezone.now(), valid_to=timezone.now() + datetime.timedelta(days=90),
            fingerprint_sha256=":".join([f"{(i % 256):02X}" for i in range(32)]), algorithm="RSA",
        )
        MonitoredEndpoint.objects.create(name="hr-portal", url="https://hr.example.com", certificate=cert)
        resp = client.get(f"/plugins/ssl/certificates/{cert.pk}/")
        assert resp.status_code == 200
        assert b"hr-portal" in resp.content
```

- [ ] **Step 4: Run, restart, lint, CHANGELOG, commit**

```bash
docker cp tests/. netbox-ssl-netbox-1:/tmp/plugin_tests/ && docker cp pytest.ini netbox-ssl-netbox-1:/tmp/plugin_tests/pytest.ini \
  && docker exec netbox-ssl-netbox-1 /opt/netbox/venv/bin/python -m pytest /tmp/plugin_tests/test_monitored_endpoint_views.py -v --tb=short
docker-compose restart netbox netbox-worker
ruff check netbox_ssl/views/certificates.py
```
Add to `CHANGELOG.md` `## [Unreleased]` → `### Added`:
```markdown
- **Website-centric certificate monitoring** ([#149](https://github.com/ctrl-alt-automate/netbox-ssl/issues/149)):
  a new **Monitored Endpoints** feature tracks the certificate each website/URL
  presents over time. A scheduled "Monitored Endpoint Poll" script re-scrapes
  each endpoint (reusing the URL-import TLS scraper + security model), links the
  certificate it finds, records rotation history, and fires NetBox events on
  unreachable / rotated / untrusted endpoints. Endpoints can be added manually,
  bulk-imported from CSV, or auto-created from the URL import flow. A certificate's
  detail page now lists every website presenting it. One additive migration.
```
```bash
git add netbox_ssl/templates/ netbox_ssl/views/certificates.py CHANGELOG.md tests/test_monitored_endpoint_views.py
git commit -m "feat: add endpoint rotation tab + certificate reverse tab (#149)"
```

---

## Final verification

- [ ] **Run all new test files together** (cross-contamination gate):

```bash
docker cp tests/. netbox-ssl-netbox-1:/tmp/plugin_tests/ && docker cp pytest.ini netbox-ssl-netbox-1:/tmp/plugin_tests/pytest.ini \
  && docker exec netbox-ssl-netbox-1 /opt/netbox/venv/bin/python -m pytest \
       /tmp/plugin_tests/test_monitored_endpoint_model.py /tmp/plugin_tests/test_url_cert_import.py \
       /tmp/plugin_tests/test_endpoint_monitor.py /tmp/plugin_tests/test_endpoint_poll_script.py \
       /tmp/plugin_tests/test_monitored_endpoint_views.py /tmp/plugin_tests/test_script_objectvar.py -v --tb=short
```
Expected: all green.

- [ ] **Django system checks + live smoke**

```bash
docker exec netbox-ssl-netbox-1 python /opt/netbox/netbox/manage.py check --tag netbox_ssl
```
Then load `/plugins/ssl/monitored-endpoints/`, add an endpoint, and confirm the detail page + the certificate's Monitored Endpoints tab.

- [ ] **Open PR to `dev`** with `Closes #149`, crediting @SerhiiZahuba. Target milestone v1.3.

## Self-review (completed during planning)

- **Spec coverage:** model + history (Task 1) ✓; shared import refactor + #106 parity (Task 2) ✓; poll service + rotation + endpoint events (Task 3) ✓; re-poll Script (Task 4) ✓; CRUD + bulk CSV + auto-create (Task 5) ✓; website-centric views + reverse tab + rotation tab + CHANGELOG (Task 6) ✓; security/#106-reuse in Global Constraints ✓; one additive migration ✓.
- **Interface consistency:** `scrape_and_import(url, host, port, *, sni, verify_chain, allowlist, tenant, set_discovered_url) -> ImportOutcome(certificate, created)` is identical in Tasks 2/3/5; `poll_endpoint(endpoint, *, allowlist) -> PollResult(endpoint, status, rotated, events_fired)` identical in Tasks 3/4; `MonitoredEndpointStatusChoices.STATUS_*`, `MonitoredEndpoint.cert_history`, `Certificate.monitored_endpoints`, the `EVENT_ENDPOINT_*` names, and the `monitoredendpoint*` URL names are used consistently. **Spec correction:** `rotated` lives on `PollResult`, not `ImportOutcome` (the import service is endpoint-agnostic) — noted intentionally.
- **Placeholders:** Tasks 1–4 and 6 carry complete code + full test code. Task 5 is NetBox CRUD boilerplate, intentionally specified as "mirror the exact `ExternalSource` counterpart" with explicit per-file field/column/filter lists — the established, declarative pattern an engineer reproduces rather than invents; the one novel piece (the #106 auto-create hook) is given as complete code.
