#!/bin/sh

CERTS_DIR=/certs

cat > config.json <<EOF
{
  "Debug": true,
  "FQDN": "${FQDN}",
  "AccountKeyPath": "${CERTS_DIR}/account.key",
  "AccountJSONPath": "${CERTS_DIR}/account.json",
  "AccountEmail": "${ACCOUNT_EMAIL}",
  "ServerCertPath": "${CERTS_DIR}/${FQDN}.crt",
  "ServerKeyPath": "${CERTS_DIR}/${FQDN}.key",
  "CloudflareEmail": "${CLOUDFLARE_EMAIL}",
  "CloudflareSecret": "${CLOUDFLARE_SECRET}",
  "CloudflareZoneID": "${CLOUDFLARE_ZONE_ID}"
}
EOF

./lecert -config ./config.json
