"""
URL Certificate Import view (#106).

Single step-based view mirroring CertificateBulkDataImportView:
1. GET                     -> upload form (step='input')
2. POST (csv)              -> parse + preview (step='preview'), rows stashed in session
3. POST (confirm=yes)      -> scrape each URL over TLS, import certs (step='result')

Each row is validated for SSRF (HTTPS + private-IP/allowlist + loopback-block),
scraped via the pre-validated IP (DNS-rebinding defense), parsed, and imported
with the same serial+issuer dedup as Smart Paste. Device/VM/service/tenant
references are resolved against the requesting user's accessible objects.
"""

from __future__ import annotations

import socket

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db import transaction
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.views.generic import View

from ..models import Certificate, CertificateStatusChoices
from ..utils import CertificateParseError, CertificateParser, detect_issuing_ca
from ..utils.tls_scraper import TLSScrapeError, scrape_tls_certificate
from ..utils.url_bulk_parser import parse as url_parse
from ..utils.url_validation import URLValidationError, validate_https_url


def _plugin_setting(name: str, default=None):
    return settings.PLUGINS_CONFIG.get("netbox_ssl", {}).get(name, default)


class UrlImportView(LoginRequiredMixin, View):
    """Import certificates by scraping them over TLS from a CSV of URLs."""

    template_name = "netbox_ssl/certificate_url_import.html"
    MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10 MB (per #106 scope)
    MAX_SESSION_ROWS = 500
    SESSION_KEY = "url_import_rows"

    def dispatch(self, request, *args, **kwargs):
        if not request.user.has_perm("netbox_ssl.run_urlimport"):
            messages.error(request, _("You do not have permission to run URL certificate import."))
            return redirect(reverse("plugins:netbox_ssl:certificate_list"))
        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        return render(request, self.template_name, {"step": "input"})

    def post(self, request):
        if request.POST.get("confirm") == "yes":
            return self._scan_and_import(request)
        return self._parse_and_preview(request)

    # -- step 2: parse + preview ------------------------------------------------

    def _parse_and_preview(self, request):
        content = ""
        if request.FILES.get("csv_file"):
            uploaded = request.FILES["csv_file"]
            if uploaded.size > self.MAX_UPLOAD_SIZE:
                messages.error(request, _("File too large. Maximum is 10 MB."))
                return render(request, self.template_name, {"step": "input"})
            content = uploaded.read().decode("utf-8-sig")
        else:
            content = request.POST.get("csv_text", "")

        if len(content) > self.MAX_UPLOAD_SIZE:
            messages.error(request, _("Pasted content too large."))
            return render(request, self.template_name, {"step": "input"})
        if not content.strip():
            messages.error(request, _("No data provided. Upload a CSV or paste rows."))
            return render(request, self.template_name, {"step": "input"})

        default_tenant = (request.POST.get("default_tenant") or "").strip()
        result = url_parse(content)

        if result.has_errors and not result.valid_rows:
            return render(
                request,
                self.template_name,
                {"step": "input", "errors": result.errors, "csv_text": content},
            )

        rows = result.valid_rows[: self.MAX_SESSION_ROWS]
        # Stash a JSON-serializable form in the session for the confirm step.
        request.session[self.SESSION_KEY] = {
            "default_tenant": default_tenant,
            "rows": [
                {
                    "row": r.row,
                    "url": r.url,
                    "host": r.host,
                    "port": r.port,
                    "sni": r.sni,
                    "verify_chain": r.verify_chain,
                    "assigned_device": r.assigned_device,
                    "assigned_vm": r.assigned_vm,
                    "assigned_service": r.assigned_service,
                    "tenant": r.tenant,
                }
                for r in rows
            ],
        }

        return render(
            request,
            self.template_name,
            {
                "step": "preview",
                "rows": rows,
                "errors": result.errors,
                "row_count": len(rows),
                "default_tenant": default_tenant,
            },
        )

    # -- step 3: scan + import --------------------------------------------------

    def _scan_and_import(self, request):
        from tenancy.models import Tenant

        stash = request.session.pop(self.SESSION_KEY, None)
        if not stash or not stash.get("rows"):
            messages.warning(request, _("No pending URL import data found."))
            return redirect(reverse("plugins:netbox_ssl:certificate_url_import"))

        allowlist = _plugin_setting("url_import_private_cidr_allowlist", [])
        user_tenants = Tenant.objects.restrict(request.user, "view")
        default_tenant = self._resolve_tenant(stash.get("default_tenant"), user_tenants)

        outcomes = []
        imported = 0

        for row in stash["rows"]:
            outcome = self._process_row(request, row, allowlist, user_tenants, default_tenant)
            outcomes.append(outcome)
            if outcome["status"] == "imported":
                imported += 1

        if imported:
            messages.success(request, _("Imported %(n)d certificate(s) from URLs.") % {"n": imported})

        return render(
            request,
            self.template_name,
            {"step": "result", "outcomes": outcomes, "imported": imported},
        )

    def _process_row(self, request, row, allowlist, user_tenants, default_tenant):
        """Validate → scrape → parse → import a single row; return an outcome dict."""
        label = row["url"]

        # 1. SSRF validation (resolves DNS and checks every resolved IP).
        try:
            validate_https_url(row["url"], cidr_allowlist=allowlist)
        except URLValidationError as exc:
            return {"url": label, "status": "blocked", "detail": str(exc)}

        # 2. Resolve to a concrete IP and connect to THAT ip (DNS-rebinding defense).
        try:
            resolved_ip = socket.getaddrinfo(row["host"], row["port"])[0][4][0]
        except OSError as exc:
            return {"url": label, "status": "unreachable", "detail": f"DNS failed: {exc}"}

        # 3. Scrape the presented chain.
        try:
            pem = scrape_tls_certificate(
                resolved_ip,
                row["host"],
                row["port"],
                sni=row["sni"],
                verify_chain=row["verify_chain"],
            )
        except TLSScrapeError as exc:
            return {"url": label, "status": "unreachable", "detail": str(exc)}

        # 4. Parse.
        try:
            parsed = CertificateParser.parse(pem)
        except CertificateParseError as exc:
            return {"url": label, "status": "error", "detail": str(exc)}

        # 5. Dedup on serial+issuer (same as Smart Paste / bulk import).
        existing = Certificate.objects.filter(serial_number=parsed.serial_number, issuer=parsed.issuer).first()
        if existing:
            existing.last_seen_at = timezone.now()
            if not existing.discovered_via_url:
                existing.discovered_via_url = row["url"]
            existing.save(update_fields=["last_seen_at", "discovered_via_url"])
            return {"url": label, "status": "matched", "detail": parsed.common_name, "pk": existing.pk}

        # 6. Create.
        tenant = self._resolve_tenant(row.get("tenant"), user_tenants) or default_tenant
        try:
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
                    discovered_via_url=row["url"],
                    last_seen_at=timezone.now(),
                )
                cert.auto_detect_acme(save=True)
        except Exception as exc:  # noqa: BLE001 - surface per-row, don't abort the batch
            return {"url": label, "status": "error", "detail": str(exc)}

        status = "imported" if row["verify_chain"] else "imported_untrusted"
        return {"url": label, "status": status, "detail": parsed.common_name, "pk": cert.pk}

    @staticmethod
    def _resolve_tenant(ref, user_tenants):
        """Resolve a tenant name/slug/ID against the user's accessible tenants."""
        ref = (ref or "").strip()
        if not ref:
            return None
        if ref.isdigit():
            tenant = user_tenants.filter(pk=int(ref)).first()
            if tenant:
                return tenant
        return user_tenants.filter(name=ref).first() or user_tenants.filter(slug=ref).first()
