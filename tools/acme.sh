#!/usr/bin/env bash
# The certificates' gate (make acme): cserve-acme against Pebble, Let's
# Encrypt's test ACME server, with cserve answering its challenges --
# offline, on loopback. A box with no certificates yet: cserve starts on
# an empty --certs, cserve-acme gets a.localhost and b.localhost, a SIGHUP
# takes them in, and both are served by SNI under Pebble's root. A rerun
# keeps them; a --force renews, and the next SIGHUP serves the new one
# without a restart. Then plain HTTP is a 308 for the names, and
# testssl.sh (when installed) looks the TLS listener over.
#
#   tools/acme.sh [BIN]   (BIN: build/O2/bin)
#
# Pebble: `go install github.com/letsencrypt/pebble/v2/cmd/pebble@v2.8.0`
# (PEBBLE names the binary, PEBBLE_SRC its module's tree, for the test
# certificates). *.localhost resolves to loopback (RFC 6761), so Pebble's
# validator reaches cserve there.
set -uo pipefail
cd "$(dirname "$0")/.."
BIN=${1:-build/O2/bin}
PEBBLE=${PEBBLE:-$(command -v pebble || echo "$HOME/go/bin/pebble")}
PEBBLE_SRC=${PEBBLE_SRC:-$(ls -d "$HOME"/go/pkg/mod/github.com/letsencrypt/pebble/v2@*/ 2>/dev/null | tail -1)}
HTTP_PORT=5002 TLS_PORT=18443 DIR_PORT=14000 MGMT_PORT=15000
if [[ ! -x "$PEBBLE" || ! -d "$PEBBLE_SRC/test/certs" ]]; then
    echo "acme: no Pebble (PEBBLE=$PEBBLE, PEBBLE_SRC=$PEBBLE_SRC)" >&2
    exit 1
fi
MINICA="$PEBBLE_SRC/test/certs/pebble.minica.pem"

tmp=$(mktemp -d)
pebble_pid="" cserve_pid=""
cleanup() {
    [[ -n "$cserve_pid" ]] && kill "$cserve_pid" 2>/dev/null
    [[ -n "$pebble_pid" ]] && kill "$pebble_pid" 2>/dev/null
    wait 2>/dev/null
    [[ -n "${KEEP:-}" ]] && cp "$tmp/testssl.json" "$KEEP" 2>/dev/null; rm -rf "$tmp"
}
trap cleanup EXIT

pass=0 fail=0
check() { # check DESCRIPTION CMD...
    local what="$1"
    shift
    if "$@"; then
        echo "  ok  $what"
        pass=$((pass + 1))
    else
        echo "FAIL  $what"
        fail=$((fail + 1))
    fi
}

# a TCP port answering, within 10 s
wait_port() {
    for _ in $(seq 100); do
        (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

# what cserve said on stderr, waited for (10 s)
wait_said() {
    for _ in $(seq 100); do
        grep -q "$1" "$tmp/cserve.err" && return 0
        sleep 0.1
    done
    return 1
}

# the serial of the certificate the TLS listener shows for NAME
serial() {
    echo | openssl s_client -connect "127.0.0.1:$TLS_PORT" -servername "$1" 2>/dev/null |
        openssl x509 -noout -serial 2>/dev/null
}

# the HTTP status of https://NAME/ under Pebble's root, verified
served() {
    curl -s -o /dev/null -w '%{http_code}' --resolve "$1:$TLS_PORT:127.0.0.1" \
        --cacert "$tmp/root.pem" "https://$1:$TLS_PORT/hello.txt"
}

acme() {
    "$BIN/cserve-acme" --directory "https://localhost:$DIR_PORT/dir" --ca "$MINICA" \
        --account "$tmp/account.key" --certs "$tmp/certs" --challenges "$tmp/challenges" \
        --name a.localhost --name b.localhost "$@"
}

cat > "$tmp/pebble.json" <<EOF
{"pebble": {
  "listenAddress": "127.0.0.1:$DIR_PORT",
  "managementListenAddress": "127.0.0.1:$MGMT_PORT",
  "certificate": "$PEBBLE_SRC/test/certs/localhost/cert.pem",
  "privateKey": "$PEBBLE_SRC/test/certs/localhost/key.pem",
  "httpPort": $HTTP_PORT, "tlsPort": 5001,
  "ocspResponderURL": "", "externalAccountBindingRequired": false,
  "retryAfter": {"authz": 1, "order": 1}
}}
EOF
mkdir -p "$tmp/certs" "$tmp/challenges" "$tmp/www"
echo "a file" > "$tmp/www/hello.txt"
chmod 755 "$tmp/challenges"

PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 "$PEBBLE" -config "$tmp/pebble.json" \
    > "$tmp/pebble.log" 2>&1 &
pebble_pid=$!
"$BIN/cserve" --listen "127.0.0.1:$HTTP_PORT" --listen "[::1]:$HTTP_PORT" \
    --listen-tls "127.0.0.1:$TLS_PORT" --certs "$tmp/certs" \
    --acme-dir "$tmp/challenges" --root "$tmp/www" --app "$BIN/apps/hello.so" \
    > /dev/null 2> "$tmp/cserve.err" &
cserve_pid=$!
if ! wait_port "$DIR_PORT" || ! wait_port "$HTTP_PORT"; then
    echo "acme: Pebble or cserve didn't start" >&2
    cat "$tmp/pebble.log" "$tmp/cserve.err" >&2
    exit 1
fi
echo "== Pebble $($PEBBLE -version 2>&1 | head -1), cserve on an empty --certs"
check "cserve started with no names yet, and said so" grep -q "no names yet" "$tmp/cserve.err"

# 1. the first issuance
check "cserve-acme: both names issued" acme
check "their pairs in place, the key 0600" \
    test -s "$tmp/certs/a.localhost/cert.pem" -a -s "$tmp/certs/b.localhost/key.pem" \
    -a "$(stat -c %a "$tmp/certs/a.localhost/key.pem")" = 600
check "the account key made 0600" test "$(stat -c %a "$tmp/account.key")" = 600
check "no challenge answer left behind" test -z "$(ls -A "$tmp/challenges")"
kill -HUP "$cserve_pid"
check "SIGHUP: cserve read both names" wait_said "read again: 2 names"
curl -s --cacert "$MINICA" "https://localhost:$MGMT_PORT/roots/0" > "$tmp/root.pem"
check "a.localhost served over TLS, verified under Pebble's root" test "$(served a.localhost)" = 200
check "b.localhost too" test "$(served b.localhost)" = 200
first=$(serial a.localhost)

# 2. a rerun: nothing due
out=$(acme 2>&1); echo "$out" | sed "s/^/    /"
check "a rerun: both kept, nothing asked of Pebble" test "$(grep -c "days left, kept" <<<"$out")" = 2

# 3. a renewal, taken in without a restart
before=$(sha256sum < "$tmp/certs/a.localhost/cert.pem")
check "cserve-acme --force: renewed" acme --force
check "a new certificate on disk" test "$(sha256sum < "$tmp/certs/a.localhost/cert.pem")" != "$before"
kill -HUP "$cserve_pid"
sleep 0.3
second=$(serial a.localhost)
check "after SIGHUP the listener shows the new one ($first -> $second)" \
    test -n "$second" -a "$first" != "$second"
check "and still serves it, verified" test "$(served a.localhost)" = 200
check "the same cserve throughout" kill -0 "$cserve_pid"

# 4. plain HTTP
loc=$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' -H "Host: a.localhost" \
    "http://127.0.0.1:$HTTP_PORT/x?y=1")
check "plain HTTP for a name: 308 to https ($loc)" test "$loc" = "308 https://a.localhost/x?y=1"
check "plain HTTP for any other Host: 404" \
    test "$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: evil.test' "http://127.0.0.1:$HTTP_PORT/")" = 404

# 5. testssl.sh, when it's there: no finding above LOW, the untrusted
# root apart (Pebble's)
# (Arch installs it as testssl, upstream as testssl.sh)
TESTSSL=$(command -v testssl.sh || command -v testssl || true)
if [[ -n "$TESTSSL" ]]; then
    "$TESTSSL" --quiet --color 0 --warnings off --jsonfile "$tmp/testssl.json" \
        --ip 127.0.0.1 "a.localhost:$TLS_PORT" > "$tmp/testssl.out" 2>&1
    bad=$(python3 -I - "$tmp/testssl.json" <<'EOF'
import json, sys
found = json.load(open(sys.argv[1]))
skip = {"cert_trust", "cert_chain_of_trust", "cert_caIssuers", "cert_crlDistributionPoints",
        "cert_ocspURL", "OCSP_stapling", "cert_mustStapleExtension", "DNS_CAArecord",
        "cert_extlifeSpan", "cert_revocation", "scanProblem", "engine_problem"}
# the grade, when the only thing capping it is that same untrusted chain
caps = [f["finding"] for f in found if f["id"].startswith("grade_cap_reason")]
if caps and all("chain of trust" in c for c in caps):
    skip.add("overall_grade")
print("\n".join(f"{f['id']}: {f['severity']} {f['finding']}" for f in found
                if f["severity"] in ("MEDIUM", "HIGH", "CRITICAL") and f["id"] not in skip))
EOF
)
    python3 -I - "$tmp/testssl.json" <<'EOF' | sed 's/^/    /'
import json, sys
for f in json.load(open(sys.argv[1])):
    if f["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        print(f"{f['severity']:8} {f['id']}: {f['finding']}")
EOF
    check "testssl.sh: nothing above LOW${bad:+ -- $bad}" test -z "$bad"
else
    echo "NOTE  testssl.sh isn't installed: skipped"
fi

echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
