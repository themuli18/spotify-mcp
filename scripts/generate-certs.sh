#!/bin/bash

# Create certs directory if it doesn't exist
mkdir -p certs

# Generate SSL certificates for localhost
openssl req -x509 \
    -newkey rsa:4096 \
    -keyout certs/localhost-key.pem \
    -out certs/localhost.pem \
    -days 365 \
    -nodes \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost"

# Set permissions
chmod 600 certs/localhost-key.pem
chmod 644 certs/localhost.pem

echo "SSL certificates generated successfully!"
echo "Key: certs/localhost-key.pem"
echo "Certificate: certs/localhost.pem" 