#!/bin/bash

echo "Generating root CA"
openssl genrsa -out root_ca.key 2048
openssl req -x509 -new -nodes -key root_ca.key -sha256 -days 3650 -out root_ca.crt -subj "/CN=Root CA"

echo "Generating intermediate CA"
openssl genrsa -out intermediate_ca.key 2048
openssl req -new -key intermediate_ca.key -out intermediate_ca.csr -config intermediate_ca.cnf
openssl x509 -req -in intermediate_ca.csr -CA root_ca.crt -CAkey root_ca.key \
    -CAcreateserial -out intermediate_ca.crt -days 3650 \
    -extfile intermediate_ca.cnf -extensions v3_ca
openssl x509 -in intermediate_ca.crt -text -noout

echo "Generating server certificates"
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -config server.cnf
openssl x509 -req -in server.csr -CA intermediate_ca.crt -CAkey intermediate_ca.key \
    -CAcreateserial -out server.crt -days 365 -sha256 \
    -extfile server.cnf -extensions req_ext

echo "Generating client certificates"
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -config client.cnf
openssl x509 -req -in client.csr -CA intermediate_ca.crt -CAkey intermediate_ca.key -CAcreateserial -out client.crt -days 365 -sha256

echo "Generating rogue CA"
openssl genrsa -out rogue_ca.key 2048
openssl req -x509 -new -nodes -key rogue_ca.key -sha256 -days 3650 -out rogue_ca.crt -subj "/CN=Rogue CA"

echo "Generating rogue client certificates"
openssl genrsa -out rogue_client.key 2048
openssl req -new -key rogue_client.key -out rogue_client.csr -subj "/CN=rogue_client"
openssl x509 -req -in rogue_client.csr -CA rogue_ca.crt -CAkey rogue_ca.key -CAcreateserial -out rogue_client.crt -days 365 -sha256

echo "Generating wrong CN server certificates"
openssl genrsa -out wrong_cn_server.key 2048
openssl req -new -key wrong_cn_server.key -out wrong_cn_server.csr -config wrong_cn_server.cnf
openssl x509 -req -in wrong_cn_server.csr -CA intermediate_ca.crt -CAkey intermediate_ca.key \
    -CAcreateserial -out wrong_cn_server.crt -days 365 -sha256 \
    -extfile wrong_cn_server.cnf -extensions req_ext

echo "Verifying server certificates"
cat intermediate_ca.crt root_ca.crt > ca_chain.crt
openssl verify -verbose -CAfile ca_chain.crt -untrusted ca_chain.crt server.crt
openssl verify -verbose -CAfile ca_chain.crt -untrusted ca_chain.crt client.crt
openssl verify -verbose -CAfile ca_chain.crt -untrusted ca_chain.crt rogue_client.crt
openssl verify -verbose -CAfile ca_chain.crt -untrusted ca_chain.crt wrong_cn_server.crt
