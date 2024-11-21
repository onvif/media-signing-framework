#!/bin/bash

# Create CA private key (provide a password for the key):
openssl ecparam -name prime256v1 -genkey -noout -out ca_ec.key
# openssl genrsa -aes256 -out ca_rsa.key
# openssl ecparam -name prime256v1 -genkey -noout -out ca_ec.key

# Create CA certificate (provide suitable input when asked):
# openssl req -x509 -new -nodes -key ca_ec.key -sha256 -days 1024 -out ca_ec.pem -subj "/C=PW/ST=SomeState/L=SomeCity/O=SomeOrg/OU=Test/CN=RootCA"
openssl req -x509 -new -nodes -key ca_ec.key -sha256 -days 1024 -set_serial 1 -out ca_ec.pem -subj "/O=SomeOrg/OU=Test/CN=Test RootCA" -config ./test_openssl.cnf
# openssl req -x509 -new -nodes -key ca_rsa.key -sha256 -days 1826 -out ca_rsa.crt
# openssl req -x509 -new -nodes -key ca_ec.key -sha256 -days 1826 -out ca_ec.crt

# Print the CA
openssl x509 -in ca_ec.pem -text -noout

## EC ##
# Generate test private keys
openssl ecparam -name prime256v1 -genkey -noout -out ec_signing.key
#openssl ecparam -name prime256v1 -genkey -noout -out private_signingkey_ec.pem

# Create CSR requirements file:
# openssl req -new -key ec_signing.key -out ec_signing.csr -subj "/C=PW/ST=SomeState/L=SomeCity/O=SomeOrg/OU=Test/CN=camera"
openssl req -new -key ec_signing.key -out ec_signing.csr -subj "/O=SomeOrg/OU=Test/CN=Test camera"

# Sign CSR
#openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out client.crt -days 365 -sha256 -extfile client_csr.cnf -extensions req_ext
openssl x509 -req -in ec_signing.csr -CA ca_ec.pem -CAkey ca_ec.key -CAcreateserial -out ec_signing.crt -days 365 -sha256 -extensions req_ext

# Print signed certificate
openssl x509 -in ec_signing.crt -text -noout

# Verify certificate
openssl verify -verbose -CAfile ca_ec.pem ec_signing.crt

## RSA ##
# Generate test private keys
#openssl ecparam -name prime256v1 -genkey -noout -out ec_signing.key
openssl genrsa -out rsa_signing.key 2048

# Create CSR requirements file:
# openssl req -new -key rsa_signing.key -out rsa_signing.csr -subj "/C=PW/ST=SomeState/L=SomeCity/O=SomeOrg/OU=Test/CN=camera"
openssl req -new -key rsa_signing.key -out rsa_signing.csr -subj "/O=SomeOrg/OU=Test/CN=Test camera"

# Sign CSR
#openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out client.crt -days 365 -sha256 -extfile client_csr.cnf -extensions req_ext
openssl x509 -req -in rsa_signing.csr -CA ca_ec.pem -CAkey ca_ec.key -CAcreateserial -out rsa_signing.crt -days 365 -sha256 -extensions req_ext

# Print signed certificate
openssl x509 -in rsa_signing.crt -text -noout

# Verify certificate
openssl verify -verbose -CAfile ca_ec.pem rsa_signing.crt
