# Documentation Screenshots

This folder holds every screenshot rendered in the root README and in the
published documentation site (MkDocs).

## Naming convention

All captures come in two themes:

| Pattern | Theme | Used by |
|---------|-------|---------|
| `<name>-dark.png` | NetBox dark mode (default) | Root README, docs site dark palette |
| `<name>-light.png` | NetBox light mode | docs site light palette, hi-contrast needs |

The base `<name>.png` (no suffix) form is **no longer used**. A handful of
legacy captures from the pre-playwright era are kept only when they still
appear in user-facing documentation and lack a refreshed replacement
(notably `dashboard-widget.png`).

## Catalog

| Filename (-dark and -light) | URL | Notes |
|-----------------------------|-----|-------|
| `certificate-list` | `/plugins/ssl/certificates/` | Mixed statuses, expiry badges |
| `certificate-detail` | `/plugins/ssl/certificates/{id}/` | Tabbed layout with renewal note |
| `certificate-import` | `/plugins/ssl/certificates/import/` | Smart Paste import form |
| `bulk-import` | `/plugins/ssl/certificates/bulk-import/` | CSV/JSON preview workflow |
| `assignments-list` | `/plugins/ssl/assignments/` | Service-level certificate links |
| `csr-list` / `csr-detail` | `/plugins/ssl/csrs/` | Pending / Approved / Rejected / Issued |
| `ca-list` / `ca-detail` | `/plugins/ssl/certificate-authorities/` | CA detail shows renewal instructions markdown |
| `analytics-dashboard` | `/plugins/ssl/analytics/` | Status, algorithm, expiry forecast, CA distribution |
| `compliance-report` | `/plugins/ssl/compliance-report/` | Score, severity, 90-day trend |
| `certificate-map` | `/plugins/ssl/certificate-map/` | Tenant → Device/VM → Service → Cert tree |
| `external-sources-list` / `external-source-detail` | `/plugins/ssl/external-sources/` | Lemur / Generic REST adapters |
| `dashboard-widget.png` (legacy) | NetBox home dashboard | SSL Certificate Status widget |

## Regenerating

```bash
# 1. Boot a local NetBox with the plugin mounted
docker compose up -d

# 2. Seed demo infrastructure (tenants, devices, VMs, services)
docker exec -i netbox-ssl-netbox-1 /opt/netbox/venv/bin/python \
    /opt/netbox/netbox/manage.py shell < scripts/create_test_data.py

# 3. Seed certificates, CAs, CSRs, assignments, policies
docker exec -i netbox-ssl-netbox-1 /opt/netbox/venv/bin/python \
    /opt/netbox/netbox/manage.py shell < scripts/seed_certificates.py

# 4. Backfill compliance checks and 90-day trend
docker exec -i netbox-ssl-netbox-1 /opt/netbox/venv/bin/python \
    /opt/netbox/netbox/manage.py shell < scripts/seed_compliance_runs.py

# 5. Install Playwright + requests and capture every page in both themes
pip install playwright requests && playwright install chromium
python scripts/take_screenshots.py
```

The final step writes ~28 PNGs under `docs/images/` (14 pages × 2 themes).
Override the default viewport or output dir with `--width`, `--height`,
or `--output`. See `python scripts/take_screenshots.py --help`.

## Capture guidelines

- **Viewport:** 1440×900 keeps sidebars + toolbars visible without oversized rasters.
- **Theme:** Capture dark and light in the same run so the pair stays in sync.
- **Data:** Run `seed_certificates.py` first — empty tables look broken in docs.
- **HTMX pages:** The screenshot script expands every certificate-map accordion
  before capturing, so tenants don't appear as "Loading..." placeholders.
