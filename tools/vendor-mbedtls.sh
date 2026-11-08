#!/usr/bin/env bash
# The vendored mbedtls (vendor/mbedtls/): one release's tarball (mbedtls with
# TF-PSA-Crypto), committed as it was published and checked against the
# SHA-256 its release page gives. The Makefile checks it again before every
# build, unpacks it into build/ and builds it with vendor/mbedtls/config/.
#
#   tools/vendor-mbedtls.sh 4.2.0 2bed9d71...   (the release, its SHA-256)
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $# -eq 2 ]] || { echo "usage: tools/vendor-mbedtls.sh VERSION SHA256" >&2; exit 2; }
version="$1" want="$2"
name="mbedtls-$version.tar.bz2"
url="https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-$version/$name"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL --proto '=https' --retry 4 "$url" -o "$tmp/$name"
got=$(sha256sum "$tmp/$name" | cut -d' ' -f1)
if [[ "$got" != "$want" ]]; then
    echo "vendor-mbedtls: $name's SHA-256 is $got, not $want" >&2
    exit 1
fi
rm -f vendor/mbedtls/mbedtls-*.tar.bz2
cp "$tmp/$name" vendor/mbedtls/
printf 'release %s\nurl %s\n%s %s\n' "$version" "$url" "$name" "$want" > vendor/mbedtls/VERSION
echo "vendored mbedtls $version"
