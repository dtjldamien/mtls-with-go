#!/bin/bash

echo "Cleaning up folder"
find . -type f ! -name "*.sh" ! -name "*.cnf" -delete
rm -rf newcerts
mkdir -p newcerts

# Initialize CA database
echo "Initializing CA database"
rm -f index.txt index.txt.attr serial crlnumber
touch index.txt index.txt.attr
echo '01' > serial
echo '01' > crlnumber

echo "Generating CAs"
openssl genrsa -out root_ca.key 2048

CURRENT_TIME="2025-05-01 11:40:18"
faketime "$CURRENT_TIME" openssl req -x509 -new -nodes -key root_ca.key -sha256 -days 100000 -out until_forever.pem -subj "/C=US/ST=California/L=San Francisco/O=Root Corp/CN=until_forever"
faketime "$CURRENT_TIME" openssl req -x509 -new -nodes -key root_ca.key -sha256 -days 1 -out one_day_root_ca.pem -subj "/C=US/ST=California/L=San Francisco/O=Future Corp/CN=one_day_root_ca"
faketime "$CURRENT_TIME" openssl req -x509 -new -nodes -key root_ca.key -sha256 -days 7 -out seven_day_root_ca.pem -subj "/C=US/ST=California/L=San Francisco/O=Future Corp/CN=seven_day_root_ca"
faketime "$CURRENT_TIME" openssl req -x509 -new -nodes -key root_ca.key -sha256 -days 14 -out fourteen_day_root_ca.pem -subj "/C=US/ST=California/L=San Francisco/O=Future Corp/CN=fourteen_day_root_ca"
openssl req -x509 -new -nodes -key root_ca.key -sha256 -days 365 -out root_ca.pem -subj "/C=US/ST=California/L=San Francisco/O=Root Corp/CN=root_ca"

openssl genrsa -out intermediate_ca_one.key 2048
openssl req -new -key intermediate_ca_one.key -out intermediate_ca_one.csr -subj "/C=US/ST=California/L=San Francisco/O=Intermediate Corp/CN=intermediate_ca_one" -config openssl.cnf
openssl ca -batch -config openssl.cnf -keyfile root_ca.key -cert root_ca.pem -in intermediate_ca_one.csr -out intermediate_ca_one.pem -days 90 -extensions v3_ca -notext

openssl genrsa -out intermediate_ca_two.key 2048
openssl req -new -key intermediate_ca_two.key -out intermediate_ca_two.csr -subj "/C=US/ST=California/L=San Francisco/O=Intermediate Corp/CN=intermediate_ca_two" -config openssl.cnf
openssl ca -batch -config openssl.cnf -keyfile root_ca.key -cert root_ca.pem -in intermediate_ca_two.csr -out intermediate_ca_two.pem -days 30 -extensions v3_ca -notext

openssl genrsa -out root_rogue_ca.key 2048
openssl req -x509 -new -nodes -key root_rogue_ca.key -sha256 -days 30 -out root_rogue_ca.pem -subj "/C=US/ST=California/L=San Francisco/O=Root Corp/CN=root_rogue_ca"

openssl genrsa -out intermediate_rogue_ca.key 2048
openssl req -new -key intermediate_rogue_ca.key -out intermediate_rogue_ca.csr -subj "/C=US/ST=California/L=San Francisco/O=Intermediate Corp/CN=intermediate_rogue_ca" -config openssl.cnf
openssl ca -batch -config openssl.cnf -keyfile root_rogue_ca.key -cert root_rogue_ca.pem -in intermediate_rogue_ca.csr -out intermediate_rogue_ca.pem -days 30 -extensions v3_ca -notext

# Create CA chain
cat intermediate_ca_two.pem intermediate_ca_one.pem root_ca.pem > ca_chain.pem

echo "Generating server certificates"
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/C=US/ST=California/L=San Francisco/O=Server Corp/CN=server" -config openssl.cnf
openssl ca -batch -config openssl.cnf -keyfile intermediate_ca_two.key -cert intermediate_ca_two.pem -in server.csr -out server.pem -days 365 -extensions usr_cert -notext

echo "Generating envoy certificates"
openssl genrsa -out envoy.key 2048
openssl req -new -key envoy.key -out envoy.csr -subj "/C=US/ST=California/L=San Francisco/O=Server Corp/CN=envoy" -config openssl.cnf
openssl ca -batch -config openssl.cnf -keyfile intermediate_ca_two.key -cert intermediate_ca_two.pem -in envoy.csr -out envoy.pem -days 365 -extensions usr_cert -notext

echo "Generating client certificates"
openssl genrsa -out revoked_client_one.key 2048
openssl req -new -key revoked_client_one.key -out revoked_client_one.csr -subj "/C=US/ST=California/L=San Francisco/O=Client Corp/CN=revoked_client_one" -config openssl.cnf
openssl ca -batch -config openssl.cnf -keyfile intermediate_ca_one.key -cert intermediate_ca_one.pem -in revoked_client_one.csr -out revoked_client_one.pem -days 365 -extensions usr_cert -notext
openssl ca -config openssl.cnf -keyfile intermediate_ca_one.key -cert intermediate_ca_one.pem -revoke revoked_client_one.pem
openssl ca -config openssl.cnf -keyfile intermediate_ca_one.key -cert intermediate_ca_one.pem -gencrl -crldays 30 -out crl_intermediate_one.pem

openssl genrsa -out revoked_client_two.key 2048
openssl req -new -key revoked_client_two.key -out revoked_client_two.csr -subj "/C=US/ST=California/L=San Francisco/O=Client Corp/CN=revoked_client_two" -config openssl.cnf
openssl ca -batch -config openssl.cnf -keyfile intermediate_ca_two.key -cert intermediate_ca_two.pem -in revoked_client_two.csr -out revoked_client_two.pem -days 365 -extensions usr_cert -notext
openssl ca -config openssl.cnf -keyfile intermediate_ca_two.key -cert intermediate_ca_two.pem -revoke revoked_client_two.pem
openssl ca -config openssl.cnf -keyfile intermediate_ca_two.key -cert intermediate_ca_two.pem -gencrl -crldays 30 -out crl_intermediate_two.pem

cat crl_intermediate_one.pem crl_intermediate_two.pem > crl.pem

openssl genrsa -out valid_client_one.key 2048
openssl req -new -key valid_client_one.key -out valid_client_one.csr -subj "/C=US/ST=California/L=San Francisco/O=Client Corp/CN=valid_client_one" -config openssl.cnf
openssl ca -batch -config openssl.cnf -keyfile intermediate_ca_one.key -cert intermediate_ca_one.pem -in valid_client_one.csr -out valid_client_one.pem -days 365 -extensions usr_cert -notext

openssl genrsa -out valid_client_two.key 2048
openssl req -new -key valid_client_two.key -out valid_client_two.csr -subj "/C=US/ST=California/L=San Francisco/O=Client Corp/CN=valid_client_two" -config openssl.cnf
openssl ca -batch -config openssl.cnf -keyfile intermediate_ca_two.key -cert intermediate_ca_two.pem -in valid_client_two.csr -out valid_client_two.pem -days 365 -extensions usr_cert -notext

openssl genrsa -out rogue_client.key 2048
openssl req -new -key rogue_client.key -out rogue_client.csr -subj "/C=US/ST=California/L=San Francisco/O=Client Corp/CN=rogue_client" -config openssl.cnf
openssl ca -batch -config openssl.cnf -keyfile intermediate_rogue_ca.key -cert intermediate_rogue_ca.pem -in rogue_client.csr -out rogue_client.pem -days 365 -extensions usr_cert -notext

echo "Verifying certificates against CRL"
openssl verify -CAfile ca_chain.pem -crl_check -CRLfile crl.pem server.pem
openssl verify -CAfile ca_chain.pem -crl_check -CRLfile crl.pem valid_client_one.pem
openssl verify -CAfile ca_chain.pem -crl_check -CRLfile crl.pem valid_client_two.pem
openssl verify -CAfile ca_chain.pem -crl_check -CRLfile crl.pem revoked_client_one.pem
openssl verify -CAfile ca_chain.pem -crl_check -CRLfile crl.pem revoked_client_two.pem
openssl verify -CAfile ca_chain.pem -crl_check -CRLfile crl.pem rogue_client.pem
