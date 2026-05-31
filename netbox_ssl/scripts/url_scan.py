"""
Certificate URL Scan (#106).

A NetBox Script that scrapes certificates over TLS from a pasted CSV of URLs and
imports them — the batch / long-running counterpart to the interactive
UrlImportView. Runs outside the request cycle so large scans don't block the UI.

Each row: SSRF-validate (HTTPS + private-IP allowlist + loopback block) → resolve
to a concrete IP and connect to that IP (DNS-rebinding defense) → scrape the
presented chain → parse → import with serial+issuer dedup.
"""

import socket

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from extras.scripts import Script, TextVar

from netbox_ssl.models import Certificate, CertificateStatusChoices
from netbox_ssl.utils import CertificateParseError, CertificateParser, detect_issuing_ca
from netbox_ssl.utils.tls_scraper import TLSScrapeError, scrape_tls_certificate
from netbox_ssl.utils.url_bulk_parser import parse as url_parse
from netbox_ssl.utils.url_validation import URLValidationError, validate_https_url


class CertificateURLScan(Script):
    """Scrape certificates over TLS from a CSV of URLs and import them."""

    class Meta:
        name = "Certificate URL Scan"
        description = "Scrape TLS certificates from a CSV of URLs and import them into the inventory"
        commit_default = True
        job_timeout = 1800

    csv_text = TextVar(
        description="CSV of URLs to scan. Columns: url (required), assigned_device, "
        "assigned_vm, assigned_service, tenant, verify_chain, sni.",
        label="URL CSV",
    )

    def get_plugin_setting(self, name, default=None):
        return settings.PLUGINS_CONFIG.get("netbox_ssl", {}).get(name, default)

    def run(self, data, commit):
        allowlist = self.get_plugin_setting("url_import_private_cidr_allowlist", [])
        result = url_parse(data.get("csv_text", ""))

        for err in result.errors:
            self.log_warning(f"Row {err.row} [{err.field}]: {err.message}")

        if not result.valid_rows:
            self.log_failure("No valid URL rows to scan.")
            return "0 imported"

        imported = matched = failed = blocked = 0

        for row in result.valid_rows:
            try:
                validate_https_url(row.url, cidr_allowlist=allowlist)
            except URLValidationError as exc:
                self.log_warning(f"{row.url}: blocked — {exc}")
                blocked += 1
                continue

            try:
                resolved_ip = socket.getaddrinfo(row.host, row.port)[0][4][0]
            except OSError as exc:
                self.log_warning(f"{row.url}: DNS resolution failed — {exc}")
                failed += 1
                continue

            try:
                pem = scrape_tls_certificate(
                    resolved_ip, row.host, row.port, sni=row.sni, verify_chain=row.verify_chain
                )
                parsed = CertificateParser.parse(pem)
            except (TLSScrapeError, CertificateParseError) as exc:
                self.log_warning(f"{row.url}: {exc}")
                failed += 1
                continue

            existing = Certificate.objects.filter(serial_number=parsed.serial_number, issuer=parsed.issuer).first()
            if existing:
                if commit:
                    existing.last_seen_at = timezone.now()
                    if not existing.discovered_via_url:
                        existing.discovered_via_url = row.url
                    existing.save(update_fields=["last_seen_at", "discovered_via_url"])
                self.log_info(f"{row.url}: matched existing certificate {parsed.common_name}")
                matched += 1
                continue

            if not commit:
                self.log_info(f"{row.url}: would import {parsed.common_name} (dry run)")
                imported += 1
                continue

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
                        discovered_via_url=row.url,
                        last_seen_at=timezone.now(),
                    )
                    cert.auto_detect_acme(save=True)
            except Exception as exc:  # noqa: BLE001 - surface per-row
                self.log_failure(f"{row.url}: import failed — {exc}")
                failed += 1
                continue

            flag = "" if row.verify_chain else " (untrusted chain)"
            self.log_success(f"{row.url}: imported {parsed.common_name}{flag}")
            imported += 1

        summary = f"{imported} imported, {matched} matched, {blocked} blocked, {failed} failed"
        self.log_info(summary)
        return summary
