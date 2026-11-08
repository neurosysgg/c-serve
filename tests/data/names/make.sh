#!/usr/bin/env bash
# Makes the names server's fixtures (tls.h's cserve_tls_names_new()) with
# a CA of their own, whose key is thrown away: rerun it to change them.
#   ca.crt            the CA a client trusts
#   good/<name>/      a.test and b.test, each its own P-256 pair
#   renewed/a.test/   a.test again, a second certificate (a reload's)
#   wrong-key/a.test/ a.test's certificate with b.test's key
#   wrong-name/a.test/ b.test's pair, under a.test's name
#   rsa/a.test/       an RSA key and its certificate
#   not-a-name/A.test/ an uppercase directory
set -euo pipefail
cd "$(dirname "$0")"
rm -rf good renewed wrong-key wrong-name rsa not-a-name ca.crt
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
openssl ecparam -name prime256v1 -genkey -noout -out "$tmp/ca.key"
openssl req -x509 -new -key "$tmp/ca.key" -subj "/CN=c-serve names test CA" \
    -days 36500 -out ca.crt
# leaf DIR NAME [KEYSPEC]: DIR/NAME/{key,cert}.pem, the cert for NAME
leaf() {
    local dir="$1" name="$2" kind="${3:-ec}"
    mkdir -p "$dir/$name"
    if [[ "$kind" == rsa ]]; then
        openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$dir/$name/key.pem"
    else
        openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$dir/$name/key.pem"
    fi
    openssl req -new -key "$dir/$name/key.pem" -subj "/CN=$name" -out "$tmp/req.csr"
    openssl x509 -req -in "$tmp/req.csr" -CA ca.crt -CAkey "$tmp/ca.key" \
        -days 36500 -out "$dir/$name/cert.pem" \
        -extfile <(printf 'subjectAltName=DNS:%s\nbasicConstraints=CA:FALSE\n' "$name")
}
leaf good a.test
leaf good b.test
leaf renewed a.test
mkdir -p wrong-key/a.test wrong-name/a.test not-a-name
cp good/a.test/cert.pem wrong-key/a.test/
cp good/b.test/key.pem wrong-key/a.test/
cp good/b.test/cert.pem good/b.test/key.pem wrong-name/a.test/
leaf rsa a.test rsa
cp -r good/a.test not-a-name/A.test
