# Documentation Screenshots

This folder contains screenshots for the NetBox SSL Plugin documentation.

## Required Screenshots

The following screenshots are referenced in the documentation:

| Filename | Description | URL |
|----------|-------------|-----|
| `certificate-list.png` | Certificate list view with status badges | `/plugins/ssl/certificates/` |
| `certificate-detail.png` | Certificate detail page with assignments | `/plugins/ssl/certificates/{id}/` |
| `certificate-import.png` | Smart Paste import form | `/plugins/ssl/certificates/import/` |
| `assignments-list.png` | Certificate assignments list | `/plugins/ssl/assignments/` |
| `dashboard-widget.png` | SSL Certificate Status dashboard widget | `/` (scroll down) |

## Generating Screenshots

### Option 1: Automated Script

Run the provided screenshot capture script:

```bash
cd /path/to/netbox-ssl
pip install selenium
python scripts/capture_screenshots.py
```

### Option 2: Manual Capture

1. Start your NetBox development environment:
   ```bash
   docker compose up -d
   ```

2. Navigate to `http://localhost:8000` and log in (admin/admin)

3. Capture each screenshot at the URLs listed above

4. Save screenshots to:
   - `docs/images/` (for README)
   - `../netbox-ssl.wiki/images/` (for Wiki)

### Recommended Settings

- **Browser width:** 1200-1400px
- **Format:** PNG
- **Theme:** Dark mode (NetBox default)

## Notes

- Screenshots should show realistic data (certificates with various statuses)
- Include the sidebar navigation for context
- Crop to focus on the relevant UI elements if needed
