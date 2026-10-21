#!/bin/bash
# Starts EJBCA from docker-compose.yml and configures it for the CMP integration tests. It creates
# the CA TestCA and the CMP alias certrally. On an EJBCA it already configured it changes nothing.
set -euo pipefail

compose=(docker compose -f "$(dirname "$0")/docker-compose.yml")

# log prints a progress line with the time.
log() { echo "$(date '+%H:%M:%S') $*"; }

# ejbca runs the EJBCA command line in the container.
ejbca() { "${compose[@]}" exec -T ejbca /opt/keyfactor/bin/ejbca.sh "$@"; }

log "Starting EJBCA. The first start takes a few minutes."
"${compose[@]}" up -d --wait

# authenticationparameters is set last, so finding it means an earlier run finished.
if ejbca config cmp dumpalias --alias certrally 2>/dev/null | grep -q 'certrally.authenticationparameters = -;-;TestCA'; then
    log "EJBCA is already configured"
    exit 0
fi

if ! ejbca ca listcas 2>/dev/null | grep -q 'CA Name: TestCA$'; then
    ejbca ca init --caname TestCA --dn "CN=TestCA,O=Integration Test" \
        --tokenType soft --tokenPass 1234 --keyspec secp256r1 --keytype ECDSA \
        -s SHA256WithECDSA -v 3652 --policy null -certprofile ROOTCA
    log "Created TestCA"
fi

if ! ejbca config cmp listalias 2>/dev/null | grep -qx 'certrally'; then
    ejbca config cmp addalias --alias certrally
fi

# The alias serves /ejbca/publicweb/cmp/certrally. In client mode EJBCA issues certificates to
# the end entities that the tests register. A request authenticates with the end entity password
# as its shared secret or with a certificate that TestCA issued. allowautomatickeyupdate lets a
# kur replace the key of an end entity.
for setting in \
    "operationmode client" \
    "defaultca TestCA" \
    "responseprotection signature" \
    "allowautomatickeyupdate true" \
    "authenticationmodule RegTokenPwd;HMAC;EndEntityCertificate" \
    "authenticationparameters -;-;TestCA"; do
    ejbca config cmp updatealias --alias certrally --key "${setting%% *}" --value "${setting#* }"
done
log "Configured the CMP alias certrally"
