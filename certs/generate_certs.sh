#!/bin/bash

echo "Generating CA private key and self-signed certificate..."
openssl genrsa -out root_ca.key 2048
openssl req -x509 -new -nodes -key root_ca.key -sha256 -days 3650 -out root_ca.crt -subj "/CN=Root CA"

echo "Generating CA private key and self-signed certificate..."
openssl genrsa -out intermediate_ca.key 2048
openssl req -new -key intermediate_ca.key -out intermediate_ca.csr -config intermediate_ca.cnf
openssl x509 -req -in intermediate_ca.csr -CA root_ca.crt -CAkey root_ca.key \
    -CAcreateserial -out intermediate_ca.crt -days 3650 \
    -extfile intermediate_ca.cnf -extensions v3_ca
openssl x509 -in intermediate_ca.crt -text -noout

echo "Generating server private key and CSR..."
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -config server.cnf

echo "Signing server certificate with CA..."
openssl x509 -req -in server.csr -CA intermediate_ca.crt -CAkey intermediate_ca.key \
    -CAcreateserial -out server.crt -days 365 -sha256 \
    -extfile server.cnf -extensions req_ext

echo "Generating client private key and CSR..."
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -config client.cnf

echo "Signing client certificate with CA..."
openssl x509 -req -in client.csr -CA intermediate_ca.crt -CAkey intermediate_ca.key -CAcreateserial -out client.crt -days 365 -sha256

cat intermediate_ca.crt root_ca.crt > ca_chain.crt

echo "Verifying server certificate..."
openssl verify -verbose -CAfile ca_chain.crt -untrusted ca_chain.crt server.crt

echo "Verifying client certificate..."
openssl verify -verbose -CAfile ca_chain.crt -untrusted ca_chain.crt client.crt
