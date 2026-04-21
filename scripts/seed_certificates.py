#!/usr/bin/env python3
"""
Certificate seeder for NetBox SSL Plugin (demo / screenshot / integration data).

Creates a diverse set of objects so every dashboard, table, chart and detail
tab is populated:
    - 5 Certificate Authorities (public, internal, ACME)
    - ~18 Certificates spanning all statuses, algorithms, expiry buckets,
      2 tenants, wildcards, ACME certs, a renewal pair, and a self-signed
    - ~22 Certificate Assignments (Services, Devices, VMs)
    - 4 CSRs (pending, approved, rejected, issued)
    - 1 ExternalSource (Lemur demo)
    - 4 Compliance Policies covering min key size, wildcard, chain, algorithm

Run inside the NetBox container:

    docker cp scripts/seed_certificates.py netbox-ssl-netbox-1:/tmp/
    docker cp scripts/seed_certificates.py netbox-ssl-netbox-1:/tmp/seed.py
    cat scripts/seed_certificates.py | docker compose run -T --rm netbox \\
        /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py shell

Re-runs are idempotent on (common_name, issuer) — existing certificates are
left untouched; only missing rows are created.
"""

import secrets
from datetime import timedelta

from django.contrib.contenttypes.models import ContentType
from django.utils import timezone

from dcim.models import Device
from ipam.models import Service
from tenancy.models import Tenant
from virtualization.models import VirtualMachine

from netbox_ssl.models import (
    Certificate,
    CertificateAssignment,
    CertificateAuthority,
    CertificateSigningRequest,
    CompliancePolicy,
    ExternalSource,
)
from netbox_ssl.models.certificate_authorities import CATypeChoices
from netbox_ssl.models.certificates import (
    ACMEChallengeTypeChoices,
    ACMEProviderChoices,
    CertificateAlgorithmChoices,
    CertificateStatusChoices,
    ChainStatusChoices,
)
from netbox_ssl.models.compliance import (
    CompliancePolicyTypeChoices,
    ComplianceSeverityChoices,
)
from netbox_ssl.models.csr import CSRStatusChoices
from netbox_ssl.models.external_source import (
    AuthMethodChoices,
    ExternalSourceTypeChoices,
    SyncStatusChoices,
)

NOW = timezone.now()


def _fp() -> str:
    """Generate a unique SHA256-style fingerprint (64 hex chars, colon-separated)."""
    raw = secrets.token_hex(32)
    return ":".join(raw[i : i + 2].upper() for i in range(0, 64, 2))


def _serial() -> str:
    """Generate a unique hex serial."""
    return secrets.token_hex(16).upper()


print("=" * 70)
print("Seeding NetBox SSL certificate data")
print("=" * 70)

tenant_prod = Tenant.objects.get(slug="production")
tenant_dev = Tenant.objects.get(slug="development")

# ======================================================================
# CERTIFICATE AUTHORITIES
# ======================================================================
print("\n[1/7] Creating Certificate Authorities...")

cas_data = [
    {
        "name": "Let's Encrypt",
        "type": CATypeChoices.TYPE_ACME,
        "issuer_pattern": "let's encrypt",
        "website_url": "https://letsencrypt.org/",
        "portal_url": "https://letsencrypt.org/getting-started/",
        "contact_email": "security@letsencrypt.org",
        "description": "Free, automated, open certificate authority.",
        "renewal_instructions": (
            "## Let's Encrypt renewal\n\n"
            "1. Ensure HTTP-01 or DNS-01 challenge reaches the ACME server.\n"
            "2. Run `certbot renew --dry-run`.\n"
            "3. On success, restart the web server."
        ),
    },
    {
        "name": "DigiCert",
        "type": CATypeChoices.TYPE_PUBLIC,
        "issuer_pattern": "digicert",
        "website_url": "https://www.digicert.com/",
        "portal_url": "https://www.digicert.com/account/",
        "contact_email": "support@digicert.com",
        "description": "Enterprise-grade public CA for OV/EV certificates.",
        "renewal_instructions": (
            "## DigiCert renewal\n\n"
            "1. Log in to CertCentral.\n"
            "2. Generate a new CSR (RSA 2048+) and submit renewal order.\n"
            "3. Complete DCV within 72h."
        ),
    },
    {
        "name": "Sectigo",
        "type": CATypeChoices.TYPE_PUBLIC,
        "issuer_pattern": "sectigo",
        "website_url": "https://sectigo.com/",
        "portal_url": "https://cert-manager.com/",
        "contact_email": "support@sectigo.com",
        "description": "Public CA offering commercial SSL and S/MIME products.",
    },
    {
        "name": "ZeroSSL",
        "type": CATypeChoices.TYPE_ACME,
        "issuer_pattern": "zerossl",
        "website_url": "https://zerossl.com/",
        "contact_email": "support@zerossl.com",
        "description": "ACME-compatible free/paid public CA.",
    },
    {
        "name": "Janus Internal CA",
        "type": CATypeChoices.TYPE_INTERNAL,
        "issuer_pattern": "janus internal ca",
        "description": "Internal PKI for non-public services and mTLS.",
        "renewal_instructions": (
            "## Janus Internal renewal\n\n"
            "Submit a CSR through the internal PKI portal. Approvals route "
            "to the security team; SLA is 1 business day."
        ),
    },
]

cas: dict[str, CertificateAuthority] = {}
for data in cas_data:
    ca, created = CertificateAuthority.objects.get_or_create(
        name=data["name"], defaults=data
    )
    cas[data["name"]] = ca
    print(f"  {'+' if created else '.'} CA: {ca.name}")

le = cas["Let's Encrypt"]
digicert = cas["DigiCert"]
sectigo = cas["Sectigo"]
zerossl = cas["ZeroSSL"]
internal = cas["Janus Internal CA"]

# ======================================================================
# EXTERNAL SOURCE
# ======================================================================
print("\n[2/7] Creating External Source...")

ext_source, created = ExternalSource.objects.get_or_create(
    name="Lemur (demo)",
    defaults={
        "source_type": ExternalSourceTypeChoices.TYPE_LEMUR,
        "base_url": "https://lemur.example.com",
        "auth_method": AuthMethodChoices.AUTH_BEARER,
        "auth_credentials_reference": "env:LEMUR_API_TOKEN",
        "verify_ssl": True,
        "sync_interval_minutes": 60,
        "enabled": False,
        "sync_status": SyncStatusChoices.STATUS_NEW,
    },
)
print(f"  {'+' if created else '.'} External Source: {ext_source.name}")

# ======================================================================
# CERTIFICATES
# ======================================================================
print("\n[3/7] Creating Certificates...")

A = CertificateAlgorithmChoices.ALGORITHM_RSA
E = CertificateAlgorithmChoices.ALGORITHM_ECDSA
ED = CertificateAlgorithmChoices.ALGORITHM_ED25519

S_ACT = CertificateStatusChoices.STATUS_ACTIVE
S_EXP = CertificateStatusChoices.STATUS_EXPIRED
S_REP = CertificateStatusChoices.STATUS_REPLACED
S_REV = CertificateStatusChoices.STATUS_REVOKED
S_PEN = CertificateStatusChoices.STATUS_PENDING
S_ARC = CertificateStatusChoices.STATUS_ARCHIVED

certs_spec: list[dict] = [
    {"cn": "www.prod.example.com",
     "issuer": "CN=DigiCert TLS RSA SHA256 2020 CA1, O=DigiCert Inc, C=US",
     "ca": digicert, "algo": A, "key_size": 2048, "days": 180,
     "status": S_ACT, "tenant": tenant_prod,
     "sans": ["www.prod.example.com", "prod.example.com"],
     "chain": ChainStatusChoices.STATUS_VALID,
     "pkl": "vault://secret/certs/www.prod.example.com/key.pem"},
    {"cn": "api.prod.example.com",
     "issuer": "CN=R3, O=Let's Encrypt, C=US",
     "ca": le, "algo": E, "key_size": 256, "days": 60,
     "status": S_ACT, "tenant": tenant_prod,
     "sans": ["api.prod.example.com", "api-v2.prod.example.com"],
     "chain": ChainStatusChoices.STATUS_VALID,
     "acme": (ACMEProviderChoices.PROVIDER_LETSENCRYPT, ACMEChallengeTypeChoices.CHALLENGE_DNS01),
     "pkl": "vault://secret/certs/api.prod.example.com/key.pem"},
    {"cn": "*.staging.example.com",
     "issuer": "CN=R10, O=Let's Encrypt, C=US",
     "ca": le, "algo": A, "key_size": 2048, "days": 45,
     "status": S_ACT, "tenant": tenant_prod,
     "sans": ["*.staging.example.com", "staging.example.com"],
     "chain": ChainStatusChoices.STATUS_VALID,
     "acme": (ACMEProviderChoices.PROVIDER_LETSENCRYPT, ACMEChallengeTypeChoices.CHALLENGE_HTTP01),
     "pkl": "vault://secret/certs/staging-wildcard/key.pem"},
    {"cn": "admin.internal.corp",
     "issuer": "CN=Janus Internal CA, O=Example Corp, C=NL",
     "ca": internal, "algo": A, "key_size": 4096, "days": 365,
     "status": S_ACT, "tenant": tenant_prod,
     "sans": ["admin.internal.corp"],
     "chain": ChainStatusChoices.STATUS_VALID,
     "pkl": "keystore://internal-pki/admin"},
    {"cn": "db-primary.prod.example.com",
     "issuer": "CN=Janus Internal CA, O=Example Corp, C=NL",
     "ca": internal, "algo": A, "key_size": 2048, "days": 220,
     "status": S_ACT, "tenant": tenant_prod,
     "sans": ["db-primary.prod.example.com"],
     "chain": ChainStatusChoices.STATUS_VALID,
     "pkl": "vault://secret/certs/db-primary/key.pem"},
    {"cn": "lb.prod.example.com",
     "issuer": "CN=DigiCert TLS RSA SHA256 2020 CA1, O=DigiCert Inc, C=US",
     "ca": digicert, "algo": A, "key_size": 2048, "days": 25,
     "status": S_ACT, "tenant": tenant_prod,
     "sans": ["lb.prod.example.com", "admin-lb.prod.example.com"],
     "chain": ChainStatusChoices.STATUS_VALID,
     "pkl": "vault://secret/certs/lb/key.pem",
     "renewal_note": "Renew via DigiCert CertCentral portal - ticket OPS-1284."},
    {"cn": "mail.example.com",
     "issuer": "CN=Sectigo RSA Domain Validation Secure Server CA, O=Sectigo Limited, C=GB",
     "ca": sectigo, "algo": A, "key_size": 2048, "days": 8,
     "status": S_ACT, "tenant": tenant_prod,
     "sans": ["mail.example.com", "smtp.example.com", "imap.example.com"],
     "chain": ChainStatusChoices.STATUS_VALID,
     "pkl": "vault://secret/certs/mail/key.pem"},
    {"cn": "mtls.prod.example.com",
     "issuer": "CN=Janus Internal CA, O=Example Corp, C=NL",
     "ca": internal, "algo": ED, "key_size": 256, "days": 200,
     "status": S_ACT, "tenant": tenant_prod,
     "sans": ["mtls.prod.example.com"],
     "chain": ChainStatusChoices.STATUS_SELF_SIGNED,
     "pkl": "vault://secret/certs/mtls/key.pem"},
    {"cn": "api-v1.example.com",
     "issuer": "CN=R3, O=Let's Encrypt, C=US",
     "ca": le, "algo": A, "key_size": 2048, "days": -12,
     "status": S_REP, "tenant": tenant_prod,
     "sans": ["api-v1.example.com"],
     "chain": ChainStatusChoices.STATUS_VALID,
     "acme": (ACMEProviderChoices.PROVIDER_LETSENCRYPT, ACMEChallengeTypeChoices.CHALLENGE_HTTP01),
     "pkl": "vault://secret/certs/api-v1/key.pem"},
    {"cn": "api.example.com",
     "issuer": "CN=R11, O=Let's Encrypt, C=US",
     "ca": le, "algo": E, "key_size": 256, "days": 78,
     "status": S_ACT, "tenant": tenant_prod,
     "sans": ["api.example.com", "v1.api.example.com", "v2.api.example.com"],
     "chain": ChainStatusChoices.STATUS_VALID,
     "acme": (ACMEProviderChoices.PROVIDER_LETSENCRYPT, ACMEChallengeTypeChoices.CHALLENGE_DNS01),
     "pkl": "vault://secret/certs/api/key.pem"},
    {"cn": "old.example.com",
     "issuer": "CN=Sectigo RSA Domain Validation Secure Server CA, O=Sectigo Limited, C=GB",
     "ca": sectigo, "algo": A, "key_size": 2048, "days": -14,
     "status": S_EXP, "tenant": tenant_prod,
     "sans": ["old.example.com"],
     "chain": ChainStatusChoices.STATUS_VALID,
     "pkl": "vault://secret/certs/old/key.pem"},
    {"cn": "legacy.old.example.com",
     "issuer": "CN=DigiCert TLS RSA SHA256 2020 CA1, O=DigiCert Inc, C=US",
     "ca": digicert, "algo": A, "key_size": 1024, "days": -55,
     "status": S_REV, "tenant": tenant_prod,
     "sans": ["legacy.old.example.com"],
     "chain": ChainStatusChoices.STATUS_INVALID,
     "pkl": "vault://secret/certs/legacy/key.pem"},
    {"cn": "retired.example.com",
     "issuer": "CN=Sectigo RSA Domain Validation Secure Server CA, O=Sectigo Limited, C=GB",
     "ca": sectigo, "algo": A, "key_size": 2048, "days": -400,
     "status": S_ARC, "tenant": tenant_prod,
     "sans": ["retired.example.com"],
     "chain": ChainStatusChoices.STATUS_VALID,
     "archived_days_ago": 30},
    {"cn": "dev.example.com",
     "issuer": "CN=E1, O=Let's Encrypt, C=US",
     "ca": le, "algo": E, "key_size": 256, "days": 50,
     "status": S_ACT, "tenant": tenant_dev,
     "sans": ["dev.example.com"],
     "chain": ChainStatusChoices.STATUS_VALID,
     "acme": (ACMEProviderChoices.PROVIDER_LETSENCRYPT, ACMEChallengeTypeChoices.CHALLENGE_HTTP01)},
    {"cn": "api-dev.example.com",
     "issuer": "CN=Sectigo RSA Domain Validation Secure Server CA, O=Sectigo Limited, C=GB",
     "ca": sectigo, "algo": A, "key_size": 2048, "days": 30,
     "status": S_PEN, "tenant": tenant_dev,
     "sans": ["api-dev.example.com"],
     "chain": ChainStatusChoices.STATUS_UNKNOWN},
    {"cn": "test.zerossl.example.com",
     "issuer": "CN=ZeroSSL RSA Domain Secure Site CA, O=ZeroSSL, C=AT",
     "ca": zerossl, "algo": A, "key_size": 2048, "days": 120,
     "status": S_ACT, "tenant": tenant_dev,
     "sans": ["test.zerossl.example.com"],
     "chain": ChainStatusChoices.STATUS_VALID,
     "acme": (ACMEProviderChoices.PROVIDER_ZEROSSL, ACMEChallengeTypeChoices.CHALLENGE_HTTP01)},
    {"cn": "vm-web-dev.example.com",
     "issuer": "CN=R3, O=Let's Encrypt, C=US",
     "ca": le, "algo": A, "key_size": 2048, "days": 89,
     "status": S_ACT, "tenant": tenant_dev,
     "sans": ["vm-web-dev.example.com"],
     "chain": ChainStatusChoices.STATUS_VALID,
     "acme": (ACMEProviderChoices.PROVIDER_LETSENCRYPT, ACMEChallengeTypeChoices.CHALLENGE_HTTP01)},
    {"cn": "orphan.unknown.example.com",
     "issuer": "CN=Sectigo RSA Domain Validation Secure Server CA, O=Sectigo Limited, C=GB",
     "ca": sectigo, "algo": A, "key_size": 2048, "days": 17,
     "status": S_ACT, "tenant": None,
     "sans": ["orphan.unknown.example.com"],
     "chain": ChainStatusChoices.STATUS_NO_CHAIN},
]

certs_by_cn: dict[str, Certificate] = {}
created_count = 0
for spec in certs_spec:
    valid_from = NOW - timedelta(days=365 if spec["days"] > 0 else 90)
    valid_to = NOW + timedelta(days=spec["days"])

    existing = Certificate.objects.filter(
        common_name=spec["cn"], issuer=spec["issuer"]
    ).first()
    if existing:
        certs_by_cn[spec["cn"]] = existing
        print(f"  . Certificate: {spec['cn']} [exists]")
        continue

    cert_kwargs = dict(
        common_name=spec["cn"],
        serial_number=_serial(),
        fingerprint_sha256=_fp(),
        issuer=spec["issuer"],
        valid_from=valid_from,
        valid_to=valid_to,
        sans=spec["sans"],
        key_size=spec["key_size"],
        algorithm=spec["algo"],
        status=spec["status"],
        tenant=spec["tenant"],
        issuing_ca=spec["ca"],
        chain_status=spec["chain"],
        chain_validated_at=NOW,
        chain_depth=3 if spec["chain"] == ChainStatusChoices.STATUS_VALID else None,
        private_key_location=spec.get("pkl", ""),
        renewal_note=spec.get("renewal_note", ""),
    )

    if "acme" in spec:
        provider, challenge = spec["acme"]
        cert_kwargs.update(
            is_acme=True,
            acme_provider=provider,
            acme_challenge_type=challenge,
            acme_auto_renewal=True,
            acme_account_email="acme@example.com",
            acme_server_url="https://acme-v02.api.letsencrypt.org/directory",
            acme_last_renewed=NOW - timedelta(days=60),
            acme_renewal_days=30,
        )

    if "archived_days_ago" in spec:
        cert_kwargs["archived_at"] = NOW - timedelta(days=spec["archived_days_ago"])

    cert = Certificate.objects.create(**cert_kwargs)
    certs_by_cn[spec["cn"]] = cert
    created_count += 1
    print(f"  + Certificate: {cert.common_name} [{cert.status}, {cert.days_remaining}d]")

# Wire up replaced_by for the renewal pair
old_cert = certs_by_cn.get("api-v1.example.com")
new_cert = certs_by_cn.get("api.example.com")
if old_cert and new_cert and old_cert.replaced_by_id != new_cert.pk:
    old_cert.replaced_by = new_cert
    old_cert.save(update_fields=["replaced_by"])
    print(f"  > Linked {old_cert.common_name} replaced_by {new_cert.common_name}")

print(f"  Total certificates created this run: {created_count}")

# ======================================================================
# ASSIGNMENTS
# ======================================================================
print("\n[4/7] Creating Certificate Assignments...")

service_ct = ContentType.objects.get_for_model(Service)
device_ct = ContentType.objects.get_for_model(Device)
vm_ct = ContentType.objects.get_for_model(VirtualMachine)


def _service(parent_name: str, port: int) -> Service | None:
    """Look up a service by parent device/VM name and port."""
    try:
        dev = Device.objects.get(name=parent_name)
        return Service.objects.filter(
            parent_object_type=device_ct,
            parent_object_id=dev.pk,
            ports__contains=[port],
        ).first()
    except Device.DoesNotExist:
        pass
    try:
        vm = VirtualMachine.objects.get(name=parent_name)
        return Service.objects.filter(
            parent_object_type=vm_ct,
            parent_object_id=vm.pk,
            ports__contains=[port],
        ).first()
    except VirtualMachine.DoesNotExist:
        return None


assignments_plan = [
    ("www.prod.example.com", "web-prod-01", 443),
    ("www.prod.example.com", "web-prod-02", 443),
    ("www.prod.example.com", "lb-prod-01", 443),
    ("api.prod.example.com", "vm-api-prod-01", 8443),
    ("api.example.com", "vm-api-prod-01", 8443),
    ("admin.internal.corp", "lb-prod-01", 8443),
    ("db-primary.prod.example.com", "db-prod-01", 3307),
    ("lb.prod.example.com", "lb-prod-01", 443),
    ("mail.example.com", "web-prod-01", 443),
    ("mtls.prod.example.com", "vm-web-prod-01", 443),
    ("mtls.prod.example.com", "vm-web-prod-02", 443),
    ("*.staging.example.com", "web-prod-02", 443),
    ("dev.example.com", "web-dev-01", 443),
    ("vm-web-dev.example.com", "vm-web-dev-01", 443),
    ("test.zerossl.example.com", "vm-api-dev-01", 8443),
]

assign_created = 0
for cert_cn, parent_name, port in assignments_plan:
    cert = certs_by_cn.get(cert_cn)
    svc = _service(parent_name, port)
    if not cert or not svc:
        print(f"  ! skipped {cert_cn} -> {parent_name}:{port} (missing data)")
        continue
    _, created = CertificateAssignment.objects.get_or_create(
        certificate=cert,
        assigned_object_type=service_ct,
        assigned_object_id=svc.pk,
        defaults={"is_primary": True, "notes": ""},
    )
    if created:
        assign_created += 1
        print(f"  + {cert.common_name} -> {parent_name}:{port}")
    else:
        print(f"  . {cert.common_name} -> {parent_name}:{port} [exists]")

print(f"  Total assignments created this run: {assign_created}")

# ======================================================================
# CSRs
# ======================================================================
print("\n[5/7] Creating Certificate Signing Requests...")

csr_data = [
    {"common_name": "new-service.prod.example.com",
     "organization": "Example Corp",
     "country": "NL",
     "sans": ["new-service.prod.example.com"],
     "key_size": 4096,
     "algorithm": "RSA",
     "status": CSRStatusChoices.STATUS_PENDING},
    {"common_name": "vault.prod.example.com",
     "organization": "Example Corp",
     "organizational_unit": "Platform",
     "country": "NL",
     "sans": ["vault.prod.example.com"],
     "key_size": 256,
     "algorithm": "ECDSA",
     "status": CSRStatusChoices.STATUS_APPROVED},
    {"common_name": "insecure.dev.example.com",
     "country": "NL",
     "sans": ["insecure.dev.example.com"],
     "key_size": 1024,
     "algorithm": "RSA",
     "status": CSRStatusChoices.STATUS_REJECTED},
    {"common_name": "api.example.com",
     "organization": "Example Corp",
     "country": "NL",
     "sans": ["api.example.com"],
     "key_size": 256,
     "algorithm": "ECDSA",
     "status": CSRStatusChoices.STATUS_ISSUED},
]

_DUMMY_CSR = (
    "-----BEGIN CERTIFICATE REQUEST-----\n"
    "MIICijCCAXICAQAwRTELMAkGA1UEBhMCTkwxFTATBgNVBAoMDEV4YW1wbGUgQ29y\n"
    "cDEfMB0GA1UEAwwWbmV3LXNlcnZpY2UucHJvZC5leGFtcGxlMIIBIjANBgkqhkiG\n"
    "9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuPlaceholderPlaceholderPlaceholderPl\n"
    "aceholderPlaceholderPlaceholderPlaceholderPlaceholderPlaceholder\n"
    "-----END CERTIFICATE REQUEST-----\n"
)

for data in csr_data:
    existing = CertificateSigningRequest.objects.filter(common_name=data["common_name"]).first()
    if existing:
        print(f"  . CSR: {existing.common_name} [exists]")
        continue
    csr = CertificateSigningRequest.objects.create(
        fingerprint_sha256=_fp(),
        pem_content=_DUMMY_CSR,
        **data,
    )
    print(f"  + CSR: {csr.common_name} [{csr.status}]")

# ======================================================================
# COMPLIANCE POLICIES
# ======================================================================
print("\n[6/7] Creating Compliance Policies...")

policies = [
    {"name": "Minimum key size 2048",
     "policy_type": CompliancePolicyTypeChoices.TYPE_MIN_KEY_SIZE,
     "severity": ComplianceSeverityChoices.SEVERITY_CRITICAL,
     "parameters": {"min_bits": 2048},
     "enabled": True,
     "description": "Block RSA keys smaller than 2048 bits."},
    {"name": "No wildcard certificates",
     "policy_type": CompliancePolicyTypeChoices.TYPE_WILDCARD_FORBIDDEN,
     "severity": ComplianceSeverityChoices.SEVERITY_WARNING,
     "parameters": {},
     "enabled": True,
     "description": "Wildcard certificates require manual review."},
    {"name": "Chain of trust required",
     "policy_type": CompliancePolicyTypeChoices.TYPE_CHAIN_REQUIRED,
     "severity": ComplianceSeverityChoices.SEVERITY_WARNING,
     "parameters": {},
     "enabled": True,
     "description": "All certificates must have a complete chain."},
    {"name": "Max validity 398 days",
     "policy_type": CompliancePolicyTypeChoices.TYPE_MAX_VALIDITY_DAYS,
     "severity": ComplianceSeverityChoices.SEVERITY_INFO,
     "parameters": {"max_days": 398},
     "enabled": True,
     "description": "CA/Browser Forum baseline for publicly-trusted TLS."},
]

for data in policies:
    policy, created = CompliancePolicy.objects.get_or_create(
        name=data["name"], defaults=data
    )
    print(f"  {'+' if created else '.'} Policy: {policy.name} [{policy.severity}]")

# ======================================================================
# SUMMARY
# ======================================================================
print("\n[7/7] Summary")
print("=" * 70)
print(f"  CAs:              {CertificateAuthority.objects.count()}")
print(f"  External Sources: {ExternalSource.objects.count()}")
print(f"  Certificates:     {Certificate.objects.count()}")
print(f"    Active:         {Certificate.objects.filter(status=S_ACT).count()}")
print(f"    Expired:        {Certificate.objects.filter(status=S_EXP).count()}")
print(f"    Replaced:       {Certificate.objects.filter(status=S_REP).count()}")
print(f"    Revoked:        {Certificate.objects.filter(status=S_REV).count()}")
print(f"    Pending:        {Certificate.objects.filter(status=S_PEN).count()}")
print(f"    Archived:       {Certificate.objects.filter(status=S_ARC).count()}")
print(f"    ACME:           {Certificate.objects.filter(is_acme=True).count()}")
print(f"  Assignments:      {CertificateAssignment.objects.count()}")
print(f"  CSRs:             {CertificateSigningRequest.objects.count()}")
print(f"  Policies:         {CompliancePolicy.objects.count()}")
print("=" * 70)
print("Done.")
