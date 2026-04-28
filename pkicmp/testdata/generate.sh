#!/bin/bash
set -e

# Generate client key and CSR
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out test_client.key
openssl req -new -key test_client.key -subj "/CN=test" -out test_client.csr

# Generate CMP messages in DER format
openssl cmp -cmd ir -csr test_client.csr -newkey test_client.key -secret pass:pass -ref myref -reqout_only ir_golden.der
openssl cmp -cmd cr -csr test_client.csr -newkey test_client.key -secret pass:pass -ref myref -reqout_only cr_golden.der
openssl cmp -cmd kur -csr test_client.csr -newkey test_client.key -secret pass:pass -ref myref -reqout_only kur_golden.der
openssl cmp -cmd p10cr -csr test_client.csr -secret pass:pass -ref myref -reqout_only p10cr_golden.der

# Cleanup intermediate files
rm test_client.key test_client.csr
