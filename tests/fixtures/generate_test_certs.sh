#!/bin/bash
# Generate test certificates for bulk import testing
# Creates 15 certificates with varying properties

set -e

FIXTURES_DIR="$(dirname "$0")"
cd "$FIXTURES_DIR"

echo "Generating test certificates in $FIXTURES_DIR"

# Function to generate a self-signed certificate
generate_cert() {
    local name=$1
    local cn=$2
    local days=$3
    local key_size=$4
    local sans=$5

    echo "Generating: $name (CN=$cn, days=$days, key=$key_size)"

    # Generate private key (we won't include this in tests)
    openssl genrsa -out "${name}.key" $key_size 2>/dev/null

    # Build SAN config if provided
    if [ -n "$sans" ]; then
        cat > "${name}.cnf" << EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
C = NL
ST = Noord-Holland
L = Amsterdam
O = Test Organization
OU = IT Department
CN = $cn

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = $sans
EOF
        openssl req -new -x509 -key "${name}.key" -out "${name}.pem" -days $days -config "${name}.cnf" 2>/dev/null
        rm "${name}.cnf"
    else
        openssl req -new -x509 -key "${name}.key" -out "${name}.pem" -days $days \
            -subj "/C=NL/ST=Noord-Holland/L=Amsterdam/O=Test Organization/OU=IT Department/CN=$cn" 2>/dev/null
    fi

    # Remove private key - we only need the certificate
    rm "${name}.key"
}

# Generate certificates with various properties

# 1-3: Standard web certificates with SANs
generate_cert "cert_web_prod" "www.example.com" 365 2048 "DNS:www.example.com,DNS:example.com"
generate_cert "cert_web_staging" "staging.example.com" 365 2048 "DNS:staging.example.com,DNS:staging-api.example.com"
generate_cert "cert_web_dev" "dev.example.com" 365 2048 "DNS:dev.example.com,DNS:localhost,IP:127.0.0.1"

# 4-6: API/Internal certificates
generate_cert "cert_api_gateway" "api.example.com" 365 4096 "DNS:api.example.com,DNS:api-internal.example.com"
generate_cert "cert_api_v2" "api-v2.example.com" 730 2048 "DNS:api-v2.example.com"
generate_cert "cert_internal" "internal.corp.local" 365 2048 "DNS:internal.corp.local,DNS:*.corp.local"

# 7-9: Database/Service certificates
generate_cert "cert_postgres" "postgres.db.local" 365 2048 "DNS:postgres.db.local,DNS:pg-primary.db.local,DNS:pg-replica.db.local"
generate_cert "cert_redis" "redis.cache.local" 365 2048 "DNS:redis.cache.local"
generate_cert "cert_rabbitmq" "rabbitmq.mq.local" 365 2048 "DNS:rabbitmq.mq.local,DNS:amqp.mq.local"

# 10-12: Wildcard and multi-domain certificates
generate_cert "cert_wildcard_prod" "*.prod.example.com" 365 2048 "DNS:*.prod.example.com,DNS:prod.example.com"
generate_cert "cert_wildcard_test" "*.test.example.com" 180 2048 "DNS:*.test.example.com,DNS:test.example.com"
generate_cert "cert_multi_domain" "shop.example.com" 365 2048 "DNS:shop.example.com,DNS:store.example.com,DNS:cart.example.com,DNS:checkout.example.com"

# 13-15: Edge cases - expiring soon, long validity, no SANs
generate_cert "cert_expiring_soon" "expiring.example.com" 10 2048 "DNS:expiring.example.com"
generate_cert "cert_long_validity" "longterm.example.com" 1095 4096 "DNS:longterm.example.com"
generate_cert "cert_no_sans" "nosans.example.com" 365 2048 ""

echo ""
echo "Generated $(ls -1 *.pem 2>/dev/null | wc -l) certificates:"
ls -la *.pem

echo ""
echo "Done! Certificates are ready for testing."
