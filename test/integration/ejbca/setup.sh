#!/bin/bash
#
# References:
#   EJBCA CLI reference:
#     https://docs.keyfactor.com/ejbca/latest/command-line-interfaces
#   Certificate profile fields (incl. Allow Extension Override):
#     https://docs.keyfactor.com/ejbca/latest/certificate-profile-fields
#
set -euo pipefail

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*"; }

log "Waiting for EJBCA to start (this takes couple of minutes)..."
until curl -sf -k https://localhost:8443/ejbca/publicweb/healthcheck/ejbcahealth > /dev/null 2>&1; do
    sleep 10
    log "Still waiting..."
done
log "EJBCA is ready"

COMPOSE="docker compose -f test/integration/ejbca/docker-compose.yml"
EJBCA_CLI="$COMPOSE exec -T ejbca /opt/keyfactor/bin/ejbca.sh"

# With TLS_SETUP_ENABLED=true, EJBCA creates a "superadmin" end entity during
# first startup with a random password. Override it with a known password, then
# generate the SuperAdmin P12 keystore for SOAP WS access.
SUPERADMIN_PASS="ejbca"

$EJBCA_CLI ra setclearpwd superadmin "$SUPERADMIN_PASS"
$EJBCA_CLI batch --username superadmin -dir /tmp/
log "SuperAdmin P12 generated"

# Copy the P12 keystore out of the container and extract PEM cert/key.
$COMPOSE cp ejbca:/tmp/superadmin.p12 test/integration/ejbca/testdata/superadmin.p12
openssl pkcs12 -in test/integration/ejbca/testdata/superadmin.p12 -passin pass:"$SUPERADMIN_PASS" -nokeys -clcerts -out test/integration/ejbca/testdata/superadmin-cert.pem
openssl pkcs12 -in test/integration/ejbca/testdata/superadmin.p12 -passin pass:"$SUPERADMIN_PASS" -nocerts -nodes -out test/integration/ejbca/testdata/superadmin-key.pem
log "SuperAdmin PEM cert/key extracted"

# Create a dedicated CA for integration tests instead of using ManagementCA.
# This creates a software crypto token with an ECDSA P-256 signing key,
# then initializes the CA with a 10-year validity.
CA_NAME="TestCA"
CA_DN="CN=TestCA,O=Integration Test"

$EJBCA_CLI ca init \
    --caname "$CA_NAME" \
    --dn "$CA_DN" \
    --tokenType soft \
    --tokenPass 1234 \
    --keyspec secp256r1 \
    --keytype ECDSA \
    -s SHA256WithECDSA \
    -v 3652 \
    --policy null \
    -certprofile ROOTCA
log "TestCA created"

# Extract CA certificate (for CMP client to verify responses).
$EJBCA_CLI ca getcacert --caname "$CA_NAME" -f /dev/stdout > test/integration/ejbca/testdata/ca.pem
log "CA certificate extracted"

# Import certificate and end entity profiles.
docker exec ejbca-ejbca-1 mkdir -p /tmp/profile_import
$COMPOSE cp test/integration/ejbca/testdata/certprofile_MYENDUSER-2045382623.xml ejbca:/tmp/profile_import/
$COMPOSE cp test/integration/ejbca/testdata/entityprofile_MYENDUSER-212939389.xml ejbca:/tmp/profile_import/
$EJBCA_CLI ca importprofiles -d /tmp/profile_import
log "Certificate and end entity profiles imported"

# Configure CMP alias for integration tests.
# This creates a CMP protocol endpoint at /ejbca/publicweb/cmp/integration
# that the Go CMP client library uses for enrollment operations.
$EJBCA_CLI config cmp addalias --alias integration

# operationmode=client: EJBCA acts as the CA/RA, the CMP client sends requests
#   directly (as opposed to "ra" mode where an RA proxy mediates).
#
# authenticationmodule: semicolon-separated list of accepted authentication methods.
#   - RegTokenPwd: password-based authentication using the end entity's enrollment password.
#     Used by Initialize (IR) requests.
#   - HMAC: shared-secret MAC-based protection. Used by Initialize (IR) requests.
#   - EndEntityCertificate: certificate-based authentication using a previously issued
#     certificate. Required for Certify (CR) and Key Update (KUR) requests.
#
# authenticationparameters: semicolon-separated parameters matching each module.
#   "-" means default/any for RegTokenPwd and HMAC.
#   "TestCA" restricts EndEntityCertificate auth to certificates issued by TestCA.
#
# responseprotection=signature: EJBCA signs responses with its CA key.
#   Using "pbe" would force password-based protection on all messages, which breaks
#   certificate-authenticated flows (CR/KUR) where the certConf is signature-protected.
#
# allowautomatickeyupdate=true: allows KUR requests to automatically update the
#   end entity's key without requiring manual re-enrollment.
#
# allowupdatewithsamekey=true: permits re-enrollment with the same key pair,
#   useful for testing certificate renewal without generating a new key.
#
# defaultcertprofile/defaultca/defaulteeprofile: set the certificate profile,
#   CA, and end entity profile used for enrollments. MYENDUSER is the custom EEP
#   that allows the MYENDUSER certificate profile and all CAs.
for key_value in \
    "operationmode client" \
    "authenticationmodule RegTokenPwd;HMAC;EndEntityCertificate" \
    "authenticationparameters -;-;$CA_NAME" \
    "responseprotection signature" \
    "allowautomatickeyupdate true" \
    "allowupdatewithsamekey true" \
    "defaultcertprofile MYENDUSER" \
    "defaultca $CA_NAME" \
    "defaulteeprofile MYENDUSER"; do
    $EJBCA_CLI config cmp updatealias --alias integration --key ${key_value%% *} --value "${key_value#* }"
done
log "CMP alias configured"

log "Setup complete"
