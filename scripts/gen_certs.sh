#!/usr/bin/env bash
# Generates a local, self-signed PKI trust chain for development/testing
# only. DO NOT use these certificates in production.
#
# Produces:
#   certs/server.crt / server.key      - client API TLS (FR9)
#   certs/admin.crt  / admin.key       - admin API TLS
#   certs/admin-ca.crt / admin-ca.key  - CA used to mint admin client certs
#   certs/admin-client.crt/.key        - an example admin mTLS client cert
set -euo pipefail

OUT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/certs"
mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

DAYS=825

echo "==> Generating client API server certificate (server.crt/server.key)"
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout server.key -out server.crt -days "$DAYS" \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo "==> Generating admin API server certificate (admin.crt/admin.key)"
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout admin.key -out admin.crt -days "$DAYS" \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo "==> Generating admin mTLS CA (admin-ca.crt/admin-ca.key)"
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout admin-ca.key -out admin-ca.crt -days "$DAYS" \
  -subj "/CN=Sentinel Admin CA"

echo "==> Generating an example admin client certificate, signed by the CA above"
openssl req -newkey rsa:2048 -nodes \
  -keyout admin-client.key -out admin-client.csr \
  -subj "/CN=operator"
openssl x509 -req -in admin-client.csr \
  -CA admin-ca.crt -CAkey admin-ca.key -CAcreateserial \
  -out admin-client.crt -days "$DAYS"
rm -f admin-client.csr

chmod 600 ./*.key
echo
echo "Done. Certificates written to: $OUT_DIR"
echo "  Client API:  certs/server.crt + certs/server.key"
echo "  Admin API:   certs/admin.crt + certs/admin.key (+ certs/admin-ca.crt for mTLS)"
echo "  Admin client (for curl --cert/--key, or as an HTTPS client identity):"
echo "    certs/admin-client.crt + certs/admin-client.key"
