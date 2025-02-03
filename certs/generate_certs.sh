#!/bin/bash

echo "Generating CA private key and self-signed certificate..."
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt -subj "/CN=Local Test CA"

echo "Generating server private key and CSR..."
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -config server.cnf

echo "Signing server certificate with CA..."
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256 -extfile server.cnf -extensions req_ext

echo "Generating client private key and CSR..."
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -config client.cnf

echo "Signing client certificate with CA..."
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365 -sha256

echo "Verifying server certificate..."
openssl verify -CAfile ca.crt server.crt

echo "Verifying client certificate..."
openssl verify -CAfile ca.crt client.crt
