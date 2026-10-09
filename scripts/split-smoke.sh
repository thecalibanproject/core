#!/usr/bin/env bash
# End-to-end smoke test of split mode: Postgres + `caliban control-plane` + `caliban router` as
# separate processes, against the mock upstream. Checks: the CP seeds Postgres from the file and
# signs snapshots; the router (no config file) picks up a tenant/key/BYOK credential created on
# the CP within the poll interval; the audit chain verifies; killing the CP leaves the router
# serving (fail-static); a router restarted while the CP is down serves from its snapshot cache;
# a restarted CP keeps its state (Postgres is the source of truth) and the router resyncs.
#
# Needs docker (Postgres 17), python3, curl. Set SPLIT_DATABASE_URL to use an existing database
# instead of a throwaway container.
set -euo pipefail
cd "$(dirname "$0")/.."

WORK=$(mktemp -d)
MOCK_PORT=19000; DP=19080; CP=19081; PG_PORT=55433; PG_NAME=caliban-split-smoke-pg
POLL=1
BIN="${CARGO_TARGET_DIR:-target}/debug/caliban"
export MOCK_LOG="$WORK/mock.jsonl" CALIBAN_ADMIN_TOKEN=split-admin CALIBAN_ROUTER_TOKEN=split-router-token CALIBAN_LOG=warn
CALIBAN_KEK=$(python3 -c 'import base64,os;print(base64.b64encode(os.urandom(32)).decode())'); export CALIBAN_KEK
KEY=cal_split_$(python3 -c 'import secrets;print(secrets.token_hex(16))')
HASH=$(printf %s "$KEY" | shasum -a 256 | cut -d' ' -f1)

PIDS=()
STARTED_PG=0
cleanup() {
  for p in "${PIDS[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null || true; done
  [[ $STARTED_PG == 1 ]] && docker stop "$PG_NAME" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

pass() { printf '  \033[32m✓\033[0m %s\n' "$1"; }
fail() { printf '  \033[31m✗\033[0m %s\n' "$1"; for f in "$WORK"/*.log; do echo "--- $f"; tail -20 "$f"; done; exit 1; }
wait_http() { for _ in $(seq 100); do curl -sf "$1" >/dev/null && return 0; sleep 0.1; done; return 1; }

cargo build -q -p caliban

# ── Postgres ──
if [[ -n "${SPLIT_DATABASE_URL:-}" ]]; then
  DB_URL=$SPLIT_DATABASE_URL
else
  docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
  docker run -d --rm -p "$PG_PORT:5432" -e POSTGRES_PASSWORD=x --name "$PG_NAME" postgres:17-alpine >/dev/null
  STARTED_PG=1
  for _ in $(seq 60); do docker exec "$PG_NAME" pg_isready -U postgres -h 127.0.0.1 >/dev/null 2>&1 && break; sleep 0.5; done
  DB_URL="postgres://postgres:x@127.0.0.1:$PG_PORT/postgres"
fi

# ── keys & config (the CP's file seeds the empty database once) ──
eval "$("$BIN" gen-signing-key | sed 's/ *#.*//; s/^/export /')"
cat > "$WORK/caliban.toml" <<TOML
[server]
control_plane_addr = "127.0.0.1:$CP"

[[models]]
id = "ext/mock"
provider = "mockext"
upstream_model = "mock-external"
trust_tier = "t2_contracted"

# Shared on-prem pool: every tenant can reach local/mock.
[[providers]]
id = "mocklocal"
kind = "openai_compatible"
base_url = "http://127.0.0.1:$MOCK_PORT/v1"
trust_tier = "t0_sovereign"

[[models]]
id = "local/mock"
provider = "mocklocal"
upstream_model = "mock-local"
trust_tier = "t0_sovereign"

[[tenants]]
id = "acme"
name = "Acme"
api_key_hashes = ["$HASH"]
TOML

python3 scripts/mock_upstream.py $MOCK_PORT & PIDS+=($!)

start_cp() {
  CALIBAN_CONFIG="$WORK/caliban.toml" CALIBAN_DATABASE_URL="$DB_URL" \
    "$BIN" control-plane >>"$WORK/cp.log" 2>&1 & CP_PID=$!; PIDS+=($CP_PID)
  wait_http "http://127.0.0.1:$CP/api/v1/health" || fail "control plane did not start"
}
start_router() {
  # No config file: everything comes from the signed snapshot (or its cache).
  CALIBAN_CONFIG=/nonexistent CALIBAN_SNAPSHOT_SIGNING_KEY= CALIBAN_LOG=info,tower_http=warn \
    "$BIN" router --control-plane-url "http://127.0.0.1:$CP" --poll-interval-secs $POLL \
    --listen "127.0.0.1:$DP" --snapshot-cache "$WORK/snapshot.json" >>"$WORK/router.log" 2>&1 & DP_PID=$!; PIDS+=($DP_PID)
  wait_http "http://127.0.0.1:$DP/healthz" || fail "router did not start"
}
adm() { curl -s "http://127.0.0.1:$CP/api/v1$1" -H "authorization: Bearer $CALIBAN_ADMIN_TOKEN" -H 'content-type: application/json' "${@:2}"; }
chat_code() {
  curl -s -o "$WORK/out" -w '%{http_code}' "http://127.0.0.1:$DP/v1/chat/completions" -H "authorization: Bearer $1" \
    -H 'content-type: application/json' -d "{\"model\":\"${2:-local/mock}\",\"messages\":[{\"role\":\"user\",\"content\":\"${3:-ping}\"}]}"
}
# Waits up to N seconds for a key to work on the router.
wait_key() { for _ in $(seq $(( $2 * 10 ))); do [[ $(chat_code "$1" "${3:-local/mock}") == 200 ]] && return 0; sleep 0.1; done; return 1; }

echo "control plane (postgres)"
start_cp
curl -s "http://127.0.0.1:$CP/api/v1/health" | grep -q '"store":"postgres"' && pass "CP store is postgres" || fail "store backend: $(curl -s "http://127.0.0.1:$CP/api/v1/health")"
adm /tenants | grep -q '"id":"acme"' && pass "empty database seeded from the config file" || fail "seed"
CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$CP/api/v1/snapshot" -H "authorization: Bearer $CALIBAN_ADMIN_TOKEN")
[[ $CODE == 401 ]] && pass "snapshot endpoint rejects the admin token (401)" || fail "snapshot auth: $CODE"
ETAG=$(curl -s -D - -o /dev/null "http://127.0.0.1:$CP/api/v1/snapshot" -H "authorization: Bearer $CALIBAN_ROUTER_TOKEN" | awk 'tolower($1)=="etag:"{print $2}' | tr -d '\r')
CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$CP/api/v1/snapshot" -H "authorization: Bearer $CALIBAN_ROUTER_TOKEN" -H "if-none-match: $ETAG")
[[ -n "$ETAG" && $CODE == 304 ]] && pass "ETag / If-None-Match → 304" || fail "etag: '$ETAG' $CODE"

echo "router (split mode, no config file)"
start_router
[[ $(chat_code "$KEY") == 200 ]] && pass "seeded tenant key works on the router" || fail "seeded key: $(cat "$WORK/out")"

adm /tenants -d '{"name":"Globex"}' >/dev/null
NEWKEY=$(adm /tenants/globex/api-keys -d '{"name":"split"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["key"])')
adm /tenants/globex/provider-keys -d "{\"kind\":\"openai_compatible\",\"label\":\"mockext\",\"base_url\":\"http://127.0.0.1:$MOCK_PORT/v1\",\"api_key\":\"sk-byok-split-9876\",\"trust_tier\":\"t2_contracted\"}" | grep -q '"last4":"9876"' \
  && pass "BYOK key stored sealed via the CP" || fail "byok create"
START=$(python3 -c 'import time;print(time.time())')
wait_key "$NEWKEY" $(( POLL * 3 + 2 )) ext/mock && pass "router picked up the new tenant + key within $(python3 -c "import time;print(round(time.time()-$START,1))")s (poll ${POLL}s)" || fail "new key never reached the router: $(cat "$WORK/out")"
tail -1 "$MOCK_LOG" | grep -q '"auth": "Bearer sk-byok-split-9876"' && pass "sealed BYOK credential opened on the router (shared KEK)" || fail "byok upstream auth: $(tail -1 "$MOCK_LOG")"
python3 -c 'import sys,json;d=json.load(sys.stdin);a=[e["action"] for e in d["entries"]];assert d["chain_verified"] and a[:3]==["provider_key.create","api_key.create","tenant.create"] and a[-1]=="store.seed",d' <<<"$(adm '/audit?limit=50')" \
  && pass "audit log hash chain verifies (seed → tenant → key → BYOK)" || fail "audit: $(adm '/audit?limit=5')"

echo "fail-static"
kill $CP_PID; wait $CP_PID 2>/dev/null || true
sleep $(( POLL * 3 ))
[[ $(chat_code "$NEWKEY" ext/mock) == 200 ]] && pass "CP down: router keeps serving the last good snapshot" || fail "router after CP death: $(cat "$WORK/out")"
grep -q 'keeping last good snapshot' "$WORK/router.log" && pass "poll failures logged, snapshot kept" || fail "no fail-static log"

kill $DP_PID; wait $DP_PID 2>/dev/null || true
start_router
[[ $(chat_code "$NEWKEY" ext/mock) == 200 ]] && pass "router restarted with CP down serves from the snapshot cache" || fail "cache restart: $(cat "$WORK/out")"
grep -q 'loaded cached snapshot' "$WORK/router.log" && pass "cache verified and loaded" || fail "cache log"

echo "control plane restart (postgres is the source of truth)"
start_cp
adm /tenants | grep -q '"id":"globex"' && pass "tenant created at runtime survived the CP restart" || fail "persistence"
adm /tenants -d '{"name":"Initech"}' >/dev/null
K3=$(adm /tenants/initech/api-keys -d '{}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["key"])')
adm /tenants/initech/routes -X PUT -d '{"routes":[{"intent":"default","models":["local/mock"]}]}' | grep -q 'local/mock' && pass "routes set via CP" || fail "routes"
wait_key "$K3" $(( POLL * 3 + 2 )) && pass "router resynced after the CP came back" || fail "resync: $(cat "$WORK/out")"
echo "all split-mode smoke checks passed"
