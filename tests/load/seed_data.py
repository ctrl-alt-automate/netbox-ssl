"""Seed-data helpers for load testing NetBox SSL.

Provides:
- :func:`generate_sample_pem`: create a fresh self-signed PEM via cert_factory
- :func:`seed_netbox`: populate a NetBox instance with N dummy certificates via API

Run as ``python -m tests.load.seed_data`` to print a sample PEM to stdout.
"""

from __future__ import annotations

import os
import random
import string
import sys
from pathlib import Path

# Allow running as ``python -m tests.load.seed_data`` from the repo root
_REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO_ROOT))

from tests.cert_factory import CertFactory  # noqa: E402


def generate_sample_pem(cn: str | None = None) -> str:
    """Generate a fresh self-signed PEM with a random CN.

    Each call produces a unique certificate with a unique serial number — the
    cryptography library picks a new random serial on every call. Useful for
    load-test imports where duplicate detection must not reject the sample.
    """
    if cn is None:
        suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        cn = f"load-{suffix}.test.netbox-ssl.local"
    return CertFactory.create(cn=cn)


def seed_netbox(
    netbox_url: str,
    token: str,
    count: int = 100,
    session: object | None = None,
) -> int:
    """Import ``count`` dummy certificates into NetBox via the Smart Paste API.

    Returns the number of successfully created certificates. Requires the
    ``requests`` library (part of the ``dev`` extras).
    """
    import requests  # noqa: PLC0415 — optional dep, only needed here

    s = session or requests.Session()
    s.headers.update(
        {
            "Authorization": f"Token {token}",
            "Content-Type": "application/json",
        }
    )
    created = 0
    for _ in range(count):
        pem = generate_sample_pem()
        r = s.post(
            f"{netbox_url.rstrip('/')}/api/plugins/netbox-ssl/certificates/import/",
            json={"pem_content": pem},
            timeout=10,
        )
        if r.ok:
            created += 1
    return created


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "seed":
        url = os.environ["NETBOX_URL"]
        tok = os.environ["NETBOX_TOKEN"]
        n = int(os.environ.get("SEED_COUNT", "100"))
        print(f"Seeding {n} certificates into {url}...")
        ok = seed_netbox(url, tok, n)
        print(f"Created {ok}/{n} certificates")
    else:
        # Default: print a sample PEM
        print(generate_sample_pem())
