"""
Unit tests for the TLS certificate scraper (#106 URL Certificate Import, PR 1).

Spins a real in-process TLS server (stdlib ``ssl`` + a throwaway self-signed
cert) on 127.0.0.1 in a background thread, then scrapes it. Pure stdlib +
``cryptography`` — no NetBox/Django dependency, so it runs on the host unit lane
(`-m unit -p no:django`).
"""

import importlib.util
import socket
import ssl
import sys
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# Mock the thin NetBox/Django surface the parser import chain touches host-side.
try:
    _spec = importlib.util.find_spec("netbox")
    _NETBOX_AVAILABLE = _spec is not None and _spec.origin is not None
except (ValueError, ModuleNotFoundError):
    _NETBOX_AVAILABLE = False

if not _NETBOX_AVAILABLE and "netbox" not in sys.modules:
    # Mock ONLY the genuinely-absent NetBox packages — Django is pip-installed in
    # the unit lane and must stay real (the parser import chain reaches
    # django.db.models.functions, which a MagicMock would break). Same pattern as
    # test_parser.py; learned from issue #116.
    from unittest.mock import MagicMock

    sys.modules["netbox"] = MagicMock()
    sys.modules["netbox.plugins"] = MagicMock()

from netbox_ssl.utils.parser import CertificateParser  # noqa: E402
from netbox_ssl.utils.tls_scraper import (  # noqa: E402
    MAX_CHAIN_BYTES,
    TLSScrapeError,
    scrape_tls_certificate,
)

pytestmark = pytest.mark.unit


def _make_self_signed(cn: str = "scraper-test.local"):
    """Return (cert_pem_bytes, key_pem_bytes) for a throwaway self-signed cert."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


class _TLSServer:
    """A minimal one-shot-per-accept TLS server running in a daemon thread."""

    def __init__(self, cn: str = "scraper-test.local"):
        self.cert_pem, self.key_pem = _make_self_signed(cn)
        self._tmp = tempfile.TemporaryDirectory()
        self._cert_file = Path(self._tmp.name) / "cert.pem"
        self._key_file = Path(self._tmp.name) / "key.pem"
        self._cert_file.write_bytes(self.cert_pem)
        self._key_file.write_bytes(self.key_pem)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(5)
        self.port = self._sock.getsockname()[1]
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(str(self._cert_file), str(self._key_file))
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        self._sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                client, _ = self._sock.accept()
            except (TimeoutError, OSError):
                continue
            try:
                with self._ctx.wrap_socket(client, server_side=True) as tls:
                    tls.recv(16)
            except (ssl.SSLError, OSError):
                pass

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._sock.close()
        self._thread.join(timeout=2)
        self._tmp.cleanup()


def test_scrape_happy_path_round_trips_through_parser():
    """A scraped self-signed cert parses back to the expected CN."""
    with _TLSServer(cn="scraper-test.local") as server:
        pem = scrape_tls_certificate("127.0.0.1", "scraper-test.local", server.port, verify_chain=False)
    assert "BEGIN CERTIFICATE" in pem
    parsed = CertificateParser.parse(pem)
    assert parsed.common_name == "scraper-test.local"


def test_verify_chain_true_rejects_self_signed():
    """With verify_chain=True (default), an untrusted self-signed chain fails."""
    with _TLSServer() as server, pytest.raises(TLSScrapeError, match="handshake"):
        scrape_tls_certificate("127.0.0.1", "scraper-test.local", server.port)


def test_connection_refused_raises():
    """An unused port (nothing listening) raises a connect error."""
    # Bind+close to obtain a definitely-free port.
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    free_port = s.getsockname()[1]
    s.close()
    with pytest.raises(TLSScrapeError, match="connect|Timeout"):
        scrape_tls_certificate("127.0.0.1", "scraper-test.local", free_port, timeout=1.0)


def test_oversized_chain_raises(monkeypatch):
    """A chain larger than MAX_CHAIN_BYTES is rejected, not silently truncated."""
    monkeypatch.setattr("netbox_ssl.utils.tls_scraper.MAX_CHAIN_BYTES", 10)
    with _TLSServer() as server, pytest.raises(TLSScrapeError, match="exceeds"):
        scrape_tls_certificate("127.0.0.1", "scraper-test.local", server.port, verify_chain=False)


def test_max_chain_bytes_is_parser_cap():
    """The scraper's size cap is the single source of truth from the parser."""
    assert MAX_CHAIN_BYTES == CertificateParser.MAX_PEM_INPUT_BYTES == 65536


def test_sni_override_is_used():
    """An explicit sni overrides the host for the handshake without error."""
    with _TLSServer(cn="scraper-test.local") as server:
        pem = scrape_tls_certificate(
            "127.0.0.1",
            "wrong-host.local",
            server.port,
            sni="scraper-test.local",
            verify_chain=False,
        )
    assert CertificateParser.parse(pem).common_name == "scraper-test.local"
