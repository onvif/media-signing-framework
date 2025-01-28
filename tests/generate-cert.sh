#!/bin/bash
# MIT License
#
# Copyright (c) 2024 ONVIF. All rights reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to the following
# conditions:
#
# The above copyright notice and this permission notice (including the next paragraph)
# shall be included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
# CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR
# THE USE OR OTHER DEALINGS IN THE SOFTWARE.


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

# Concatenate certificates
cat ec_signing.crt ca_ec.pem > ec_cert_chain.pem

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

# Concatenate certificates
cat rsa_signing.crt ca_ec.pem > rsa_cert_chain.pem
