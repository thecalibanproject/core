#!/usr/bin/env bash
# End-to-end smoke test of single sign-on against a real OpenID provider: a throwaway Dex container
# (mock connector, user "Kilgore Trout" in group "authors") and `caliban control-plane` with the
# CALIBAN_OIDC_* variables. Checks: the login redirect chain ends with a session; /auth/me shows the
# user and the owner role mapped from the group; a write needs the CSRF token; logout ends the
# session; the audit log names the user and its chain verifies; break-glass use is audited.
#
# Needs docker, curl and python3, and a built binary (cargo build -p caliban).
set -euo pipefail
cd "$(dirname "$0")/.."

WORK=$(mktemp -d)
DEX_PORT=55580; CP=18081; DEX_NAME=${DEX_NAME:-caliban-sso-smoke-dex}
DEX_IMAGE=${DEX_IMAGE:-ghcr.io/dexidp/dex:v2.43.1}
BIN="${CARGO_TARGET_DIR:-target}/debug/caliban"
ISSUER="http://127.0.0.1:$DEX_PORT/dex"
SECRET=dex-smoke-secret-not-real
PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null || true; done
  docker stop "$DEX_NAME" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; [[ -f "$WORK/cp.log" ]] && tail -20 "$WORK/cp.log" >&2; exit 1; }

cat >"$WORK/dex.yaml" <<EOF
issuer: $ISSUER
storage: { type: memory }
web: { http: 0.0.0.0:5556 }
oauth2: { skipApprovalScreen: true }
staticClients:
  - id: caliban-console
    name: Caliban
    secret: $SECRET
    redirectURIs: ["http://127.0.0.1:$CP/auth/callback"]
connectors:
  - { type: mockCallback, id: mock, name: Mock }
EOF
sed -e "s/0.0.0.0:8081/127.0.0.1:$CP/; s/0.0.0.0:8080/127.0.0.1:18080/" config/caliban.example.toml >"$WORK/caliban.toml"

docker run --rm -d --name "$DEX_NAME" -p "127.0.0.1:$DEX_PORT:5556" -v "$WORK/dex.yaml:/etc/dex/config.yaml:ro" \
  "$DEX_IMAGE" dex serve /etc/dex/config.yaml >/dev/null
for _ in $(seq 1 30); do curl -sf "$ISSUER/.well-known/openid-configuration" >/dev/null && break; sleep 1; done

CALIBAN_CONFIG="$WORK/caliban.toml" CALIBAN_ADMIN_TOKEN=smoke-break-glass CALIBAN_LOG=warn \
  CALIBAN_OIDC_ISSUER="$ISSUER" CALIBAN_OIDC_CLIENT_ID=caliban-console CALIBAN_OIDC_CLIENT_SECRET="$SECRET" \
  CALIBAN_OIDC_REDIRECT_URL="http://127.0.0.1:$CP/auth/callback" CALIBAN_OIDC_SCOPES="openid profile email groups" \
  CALIBAN_OIDC_OWNER_GROUPS=authors "$BIN" control-plane >"$WORK/cp.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 30); do curl -sf "http://127.0.0.1:$CP/api/v1/health" >/dev/null && break; sleep 1; done

JAR="$WORK/jar"
API="http://127.0.0.1:$CP"
curl -s -c "$JAR" -b "$JAR" -L --max-redirs 10 -o /dev/null "$API/auth/login?return_to=%2Fapi%2Fv1%2Fhealth"
ME=$(curl -s -b "$JAR" "$API/auth/me")
python3 - "$ME" <<'EOF' || fail "/auth/me: $ME"
import json, sys
me = json.loads(sys.argv[1])
assert me["method"] == "session", me
assert me["user"]["name"] == "Kilgore Trout", me
assert me["roles"] == [{"role": "owner"}], me
EOF
CSRF=$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["csrf_token"])' "$ME")
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" -H 'content-type: application/json' -d '{"name":"Smoke"}' "$API/api/v1/tenants")
[[ $code == 403 ]] || fail "write without CSRF: $code"
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" -H "x-csrf-token: $CSRF" -H 'content-type: application/json' -d '{"name":"Smoke"}' "$API/api/v1/tenants")
[[ $code == 201 ]] || fail "write with CSRF: $code"
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" -c "$JAR" -X POST -H "x-csrf-token: $CSRF" "$API/auth/logout")
[[ $code == 200 ]] || fail "logout: $code"
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" "$API/auth/me")
[[ $code == 401 ]] || fail "session after logout: $code"
AUDIT=$(curl -s -H 'authorization: Bearer smoke-break-glass' "$API/api/v1/audit?limit=10")
python3 - "$AUDIT" <<'EOF' || fail "audit: $AUDIT"
import json, sys
a = json.loads(sys.argv[1])
assert a["chain_verified"], a
actions = [(e["action"], e["actor"]) for e in a["entries"]]
assert actions[0] == ("auth.break_glass", "break_glass"), actions
user = [actor for action, actor in actions if action == "tenant.create"][0]
assert user.startswith("kilgore@kilgore.trout <http://127.0.0.1:"), user
assert {"auth.login", "auth.logout"} <= {action for action, _ in actions}, actions
EOF
echo "OK: SSO login, CSRF, logout and audit against Dex"
