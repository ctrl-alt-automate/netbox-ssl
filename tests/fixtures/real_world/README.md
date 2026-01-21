# Real-World Certificate Fixtures

This directory contains real certificates fetched from public websites for testing purposes.

## Purpose

These certificates are used to test:
- Certificate parsing with real-world certificate structures
- CA auto-detection with actual issuer strings
- Chain validation with real certificate chains
- Different CA formats and extensions

## Certificate Sources

| File | Source | CA | Fetched |
|------|--------|----|---------||`letsencrypt_leaf.pem` | letsencrypt.org | Let's Encrypt E7 | 2025-01-21 |
| `letsencrypt_chain.pem` | letsencrypt.org | Let's Encrypt + ISRG Root X1 | 2025-01-21 |
| `digicert_leaf.pem` | www.digicert.com | DigiCert EV RSA CA G2 | 2025-01-21 |
| `digicert_chain.pem` | www.digicert.com | DigiCert full chain | 2025-01-21 |
| `sectigo_leaf.pem` | www.sectigo.com | Sectigo Public Server Auth CA | 2025-01-21 |
| `sectigo_chain.pem` | www.sectigo.com | Sectigo full chain | 2025-01-21 |

## How These Were Obtained

Certificates were fetched using OpenSSL:

```bash
# Fetch full chain
echo | openssl s_client -connect example.com:443 -showcerts 2>/dev/null | \
  awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/'

# Fetch leaf only
echo | openssl s_client -connect example.com:443 2>/dev/null | openssl x509
```

## Important Notes

1. **These certificates will expire** - They are snapshots and will eventually become invalid for chain validation tests. This is expected and even useful for testing expiry detection.

2. **Public data only** - These are public certificates that anyone can obtain by visiting the websites. No private keys are included.

3. **Refresh if needed** - Run the fetch commands above to get fresh certificates if needed for chain validation tests.

## Updating Certificates

To refresh all certificates:

```bash
cd tests/fixtures/real_world

# Let's Encrypt
echo | openssl s_client -connect letsencrypt.org:443 -showcerts 2>/dev/null | \
  awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' > letsencrypt_chain.pem
echo | openssl s_client -connect letsencrypt.org:443 2>/dev/null | \
  openssl x509 > letsencrypt_leaf.pem

# DigiCert
echo | openssl s_client -connect www.digicert.com:443 -showcerts 2>/dev/null | \
  awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' > digicert_chain.pem
echo | openssl s_client -connect www.digicert.com:443 2>/dev/null | \
  openssl x509 > digicert_leaf.pem

# Sectigo
echo | openssl s_client -connect www.sectigo.com:443 -showcerts 2>/dev/null | \
  awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' > sectigo_chain.pem
echo | openssl s_client -connect www.sectigo.com:443 2>/dev/null | \
  openssl x509 > sectigo_leaf.pem
```
