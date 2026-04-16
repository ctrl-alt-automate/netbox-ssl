"""Locust load tests for NetBox SSL.

Run against a local NetBox instance::

    NETBOX_URL=http://localhost:8000 NETBOX_TOKEN=nbt_xxx.yyy \\
        locust -f tests/load/locustfile.py --host=$NETBOX_URL

Open http://localhost:8089 for the web UI, or append
``--users 50 --spawn-rate 5 --run-time 2m --headless --csv=/tmp/locust``
for a headless scripted run.

Three user classes simulate realistic mixed workload:

- :class:`CertificateBrowseUser` — read-heavy list + filter (weight 5)
- :class:`CertificateImportUser` — write-heavy Smart Paste import (weight 1)
- :class:`CertificateDiffUser` — occasional diff API calls (weight 1)

Adjust the ``weight`` class attribute to model your workload.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from locust import HttpUser, between, task

# Make ``tests`` importable when Locust runs this file directly
_REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO_ROOT))

from tests.load.seed_data import generate_sample_pem  # noqa: E402

_TOKEN = os.environ.get("NETBOX_TOKEN")
if not _TOKEN:
    raise RuntimeError(
        "NETBOX_TOKEN env var is required. See docs/operations/load-testing.md"
    )


class CertificateBrowseUser(HttpUser):
    """Read-heavy user: list + filter + paginate."""

    wait_time = between(1, 3)
    weight = 5

    def on_start(self) -> None:
        self.client.headers.update({"Authorization": f"Token {_TOKEN}"})

    @task(5)
    def list_certificates(self) -> None:
        self.client.get(
            "/api/plugins/netbox-ssl/certificates/",
            name="GET /certificates/",
        )

    @task(2)
    def filter_active(self) -> None:
        self.client.get(
            "/api/plugins/netbox-ssl/certificates/?status=active",
            name="GET /certificates/?status=active",
        )

    @task(2)
    def paginate_page_2(self) -> None:
        self.client.get(
            "/api/plugins/netbox-ssl/certificates/?limit=50&offset=50",
            name="GET /certificates/?paginated",
        )

    @task(1)
    def filter_is_acme(self) -> None:
        self.client.get(
            "/api/plugins/netbox-ssl/certificates/?is_acme=true",
            name="GET /certificates/?is_acme=true",
        )


class CertificateImportUser(HttpUser):
    """Write-heavy user: POST Smart Paste import.

    Each request uses a freshly generated self-signed PEM so duplicate
    detection does not reject the sample. Import is CPU-bound (PEM parsing)
    so fewer concurrent users than reads.
    """

    wait_time = between(5, 15)
    weight = 1

    def on_start(self) -> None:
        self.client.headers.update(
            {
                "Authorization": f"Token {_TOKEN}",
                "Content-Type": "application/json",
            }
        )

    @task
    def import_certificate(self) -> None:
        self.client.post(
            "/api/plugins/netbox-ssl/certificates/import/",
            json={"pem_content": generate_sample_pem()},
            name="POST /certificates/import/",
        )


class CertificateDiffUser(HttpUser):
    """Occasional diff API user for snapshot comparisons."""

    wait_time = between(10, 30)
    weight = 1

    def on_start(self) -> None:
        self.client.headers.update(
            {
                "Authorization": f"Token {_TOKEN}",
                "Content-Type": "application/json",
            }
        )

    @task
    def diff_snapshots(self) -> None:
        self.client.post(
            "/api/plugins/netbox-ssl/certificates/diff/",
            json={"before": [], "after": []},
            name="POST /certificates/diff/",
        )
