#!/bin/bash
# MIT License
#
# Copyright (c) 2025 ONVIF. All rights reserved.
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


# 1. Create ROOT CA
# Create private key for Root CA
openssl ecparam -name prime256v1 -genkey -noout -out ca_ec.key

# Create Root CA certificate
openssl req -x509 -new -nodes -key ca_ec.key -sha256 -days 36500 -set_serial 1 -out ca_ec.pem -subj "/O=SomeOrg/OU=Test/CN=Test RootCA" -config ./test_openssl.cnf

# Print Root CA certificate
openssl x509 -in ca_ec.pem -text -noout


## EC ##
# 2. Create INTERMEDIATE CA (NEW STEP)
# Create private key for Intermediate CA
openssl ecparam -name prime256v1 -genkey -noout -out intermediate_ec.key

# Create CSR (Certificate Signing Request) for Intermediate CA
openssl req -new -key intermediate_ec.key -out intermediate_ec.csr -subj "/O=SomeOrg/OU=Test/CN=Test IntermediateCA"

# Sign Intermediate CSR with Root CA (Important: requires CA extensions in your cnf file)
openssl x509 -req -in intermediate_ec.csr -CA ca_ec.pem -CAkey ca_ec.key -CAcreateserial -out intermediate_ec.pem -days 730 -sha256 -extfile ./test_openssl.cnf -extensions v3_ca

# Print Intermediate CA certificate
openssl x509 -in intermediate_ec.pem -text -noout

# 3. CREATE AND SIGN END-ENTITY CERTIFICATE (MODIFIED)
# Generate test private keys
openssl ecparam -name prime256v1 -genkey -noout -out ec_signing.key

# Create CSR for end-entity certificate (e.g., camera)
openssl req -new -key ec_signing.key -out ec_signing.csr -subj "/O=SomeOrg/OU=Test/CN=Test camera-serial_no-12345"

# Sign camera's CSR with INTERMEDIATE CA (not Root CA)
openssl x509 -req -in ec_signing.csr -CA intermediate_ec.pem -CAkey intermediate_ec.key -CAcreateserial -out ec_signing.crt -days 365 -sha256 -extensions req_ext

# Print end-entity certificate
openssl x509 -in ec_signing.crt -text -noout

# 4. VERIFY AND CREATE CHAIN (MODIFIED)
# Create a file with the entire CA chain for verification
cat intermediate_ec.pem ca_ec.pem > ca_chain.pem

# Verify camera's certificate against the entire chain
openssl verify -verbose -CAfile ca_chain.pem ec_signing.crt

# Create the final certificate chain (End-entity -> Intermediate -> Root)
cat ec_signing.crt intermediate_ec.pem ca_ec.pem > ec_cert_chain.pem


## RSA ##
# Generate test private keys
#openssl ecparam -name prime256v1 -genkey -noout -out ec_signing.key
openssl genrsa -out rsa_signing.key 2048

# Create CSR for end-entity certificate (e.g., camera)
openssl req -new -key rsa_signing.key -out rsa_signing.csr -subj "/O=SomeOrg/OU=Test/CN=Test camera-serial_no-12345"

# Sign camera's CSR with INTERMEDIATE CA (not Root CA)
openssl x509 -req -in rsa_signing.csr -CA intermediate_ec.pem -CAkey intermediate_ec.key -CAcreateserial -out rsa_signing.crt -days 365 -sha256 -extensions req_ext

# Print end-entity certificate
openssl x509 -in rsa_signing.crt -text -noout

# 4. VERIFY AND CREATE CHAIN (MODIFIED)
# Create a file with the entire CA chain for verification
cat intermediate_ec.pem ca_ec.pem > ca_chain.pem

# Verify camera's certificate against the entire chain
openssl verify -verbose -CAfile ca_chain.pem rsa_signing.crt

# Create the final certificate chain (End-entity -> Intermediate -> Root)
cat rsa_signing.crt intermediate_ec.pem ca_ec.pem > rsa_cert_chain.pem
