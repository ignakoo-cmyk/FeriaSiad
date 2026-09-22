#!/bin/sh
# ──────────────────────────────────────────────────────────────────────
# Genera certificados TLS auto-firmados para desarrollo local.
# Para producción, usar Let's Encrypt (Certbot) o un certificado real.
#
# Uso:  sh nginx/gen-certs.sh
# ──────────────────────────────────────────────────────────────────────

set -e

CERTS_DIR="$(dirname "$0")/certs"
mkdir -p "$CERTS_DIR"

openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 \
  -keyout "$CERTS_DIR/key.pem" \
  -out    "$CERTS_DIR/cert.pem" \
  -subj   "/C=CL/ST=RM/L=Santiago/O=UAH/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo ""
echo "✅  Certificados generados en $CERTS_DIR/"
echo "    cert.pem  — certificado público"
echo "    key.pem   — clave privada (NO commitear al repo)"
