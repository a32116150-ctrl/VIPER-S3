#!/bin/bash
# Generate self-signed certs for HTTPS dashboard
CERT_DIR="$(cd "$(dirname "$0")" && pwd)/certs"
mkdir -p "$CERT_DIR"

if [ ! -f "$CERT_DIR/servercert.pem" ] || [ ! -f "$CERT_DIR/prvtkey.pem" ]; then
    echo "Generating self-signed certs in $CERT_DIR"
    openssl req -x509 -newkey rsa:2048 -keyout "$CERT_DIR/prvtkey.pem" \
        -out "$CERT_DIR/servercert.pem" -days 3650 -nodes \
        -subj "/CN=192.168.4.1" \
        -addext "subjectAltName=DNS:viper-s3.local,IP:192.168.4.1" 2>/dev/null
    echo "Certs generated."
fi
