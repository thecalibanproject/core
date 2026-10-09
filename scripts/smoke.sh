#!/usr/bin/env bash
# End-to-end smoke test of the `caliban standalone` binary against a mock OpenAI-compatible
# upstream (OpenAI-compatible + Anthropic Messages). Checks: PII never reaches an external model,
# responses (incl. streams) are rehydrated, sovereign models get raw text, exact cache hits,
# secrets are blocked, the Anthropic Messages API (translated and native passthrough), rate
# limits (429 + retry-after), and keys / BYOK credentials created through the control plane work
# on the data plane.
set -euo pipefail
cd "$(dirname "$0")/.."

WORK=$(mktemp -d)
MOCK_PORT=18000; DP=18080; CP=18081
export MOCK_LOG="$WORK/mock.jsonl" CALIBAN_ADMIN_TOKEN=smoke-admin
CALIBAN_KEK=$(python3 -c 'import base64,os;print(base64.b64encode(os.urandom(32)).decode())'); export CALIBAN_KEK
KEY=cal_smoke_$(python3 -c 'import secrets;print(secrets.token_hex(16))')
HASH=$(printf %s "$KEY" | shasum -a 256 | cut -d' ' -f1)
TKEY=cal_smoke_$(python3 -c 'import secrets;print(secrets.token_hex(16))')
THASH=$(printf %s "$TKEY" | shasum -a 256 | cut -d' ' -f1)
export SMOKE_ANTHROPIC_KEY=sk-ant-smoke-5678

cat > "$WORK/caliban.toml" <<TOML
[server]
router_addr = "127.0.0.1:$DP"
control_plane_addr = "127.0.0.1:$CP"

[[models]]
id = "ext/mock"
provider = "mockext"
upstream_model = "mock-external"
trust_tier = "t2_contracted"
price_in_per_mtok = 1.0
price_out_per_mtok = 2.0

[[providers]]
id = "qwen-pool"
kind = "openai_compatible"
base_url = "http://127.0.0.1:$MOCK_PORT/v1"
trust_tier = "t0_sovereign"
cache_salt = true

[[models]]
id = "local/qwen3-8b"
provider = "qwen-pool"
upstream_model = "Qwen/Qwen3-8B"
family = "qwen3"
trust_tier = "t0_sovereign"
licence = "apache-2.0"
[models.capabilities]
tools = true
reasoning = "hybrid"
reasoning_control = "enable_thinking"
inline_think_tags = true

[[models]]
id = "local/rerank"
provider = "qwen-pool"
upstream_model = "Qwen/Qwen3-Reranker-0.6B"
kind = "rerank"
trust_tier = "t0_sovereign"

[[models]]
id = "local/mock"
provider = "mocklocal"
upstream_model = "mock-local"
trust_tier = "t0_sovereign"

[[models]]
id = "anthropic/mock"
provider = "anthmock"
upstream_model = "claude-mock"
trust_tier = "t2_contracted"

[[tenants]]
id = "acme"
name = "Acme"
api_key_hashes = ["$HASH"]
  [[tenants.providers]]
  id = "mockext"
  kind = "openai_compatible"
  base_url = "http://127.0.0.1:$MOCK_PORT/v1"
  trust_tier = "t2_contracted"
  [[tenants.providers]]
  id = "mocklocal"
  kind = "openai_compatible"
  base_url = "http://127.0.0.1:$MOCK_PORT/v1"
  trust_tier = "t0_sovereign"
  [[tenants.providers]]
  id = "anthmock"
  kind = "anthropic"
  base_url = "http://127.0.0.1:$MOCK_PORT/v1"
  trust_tier = "t2_contracted"
  api_key = { env = "SMOKE_ANTHROPIC_KEY" }

[[tenants]]
id = "throttled"
name = "Throttled"
api_key_hashes = ["$THASH"]
  [[tenants.providers]]
  id = "mocklocal"
  kind = "openai_compatible"
  base_url = "http://127.0.0.1:$MOCK_PORT/v1"
  trust_tier = "t0_sovereign"

[limits.tenants.throttled]
requests_per_minute = 2
TOML

# With CALIBAN_PII_NER_DIR set, build with the L1 NER model and also check name protection.
if [[ -n "${CALIBAN_PII_NER_DIR:-}" ]]; then cargo build -q -p caliban --features ner; else cargo build -q -p caliban; fi
python3 scripts/mock_upstream.py $MOCK_PORT & MOCK_PID=$!
CALIBAN_CONFIG="$WORK/caliban.toml" CALIBAN_LOG=warn ./target/debug/caliban standalone & CAL_PID=$!
trap 'kill $MOCK_PID $CAL_PID 2>/dev/null; rm -rf "$WORK"' EXIT
# Up to 60 s: loading + hash-verifying the NER model is slow in debug builds.
for i in $(seq 300); do curl -sf "http://127.0.0.1:$DP/healthz" >/dev/null && break; [[ $i == 300 ]] && { echo "caliban did not become healthy" >&2; exit 1; }; sleep 0.2; done

pass() { printf '  \033[32m✓\033[0m %s\n' "$1"; }
fail() { printf '  \033[31m✗\033[0m %s\n' "$1"; exit 1; }
chat() { curl -s -D "$WORK/h" "http://127.0.0.1:$DP/v1/chat/completions" -H "authorization: Bearer ${2:-$KEY}" -H 'content-type: application/json' -d "$1"; }

PII='Email jane.doe@acme.com about card 4111 1111 1111 1111'
echo "data plane"
OUT=$(chat "{\"model\":\"ext/mock\",\"messages\":[{\"role\":\"user\",\"content\":\"$PII\"}]}")
grep -q 'jane.doe@acme.com' <<<"$OUT" && grep -q '4111 1111 1111 1111' <<<"$OUT" && pass "external: response rehydrated" || fail "external rehydration: $OUT"
tail -1 "$MOCK_LOG" | grep -q 'jane.doe@acme.com' && fail "external model received raw PII" || pass "external: upstream saw surrogates only"
grep -qi 'x-caliban-pii-entities: 2' "$WORK/h" && pass "pii entity header" || fail "pii header"

OUT=$(chat "{\"model\":\"ext/mock\",\"stream\":true,\"messages\":[{\"role\":\"user\",\"content\":\"$PII\"}]}")
TEXT=$(grep '^data: {' <<<"$OUT" | sed 's/^data: //' | python3 -c 'import sys,json;print("".join((json.loads(l)["choices"][0]["delta"].get("content") or "") for l in sys.stdin if json.loads(l).get("choices")))')
[[ "$TEXT" == "You said: $PII" ]] && pass "streaming: split surrogates rehydrated" || fail "stream text: $TEXT"

chat "{\"model\":\"local/mock\",\"messages\":[{\"role\":\"user\",\"content\":\"$PII\"}]}" >/dev/null
tail -1 "$MOCK_LOG" | grep -q 'jane.doe@acme.com' && pass "sovereign model receives raw text (no redaction needed)" || fail "sovereign"

REQ='{"model":"local/mock","temperature":0,"messages":[{"role":"user","content":"what is 2+2"}]}'
chat "$REQ" >/dev/null; chat "$REQ" >/dev/null
grep -qi 'x-caliban-cache: hit' "$WORK/h" && pass "exact cache hit on repeat" || fail "cache"

CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$DP/v1/chat/completions" -H "authorization: Bearer $KEY" -H 'content-type: application/json' \
  -d '{"model":"ext/mock","messages":[{"role":"user","content":"key AKIAIOSFODNN7EXAMPLE"}]}')
[[ "$CODE" == 403 ]] && pass "credentials in prompt are blocked (403)" || fail "secret block: $CODE"
CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$DP/v1/models" -H 'authorization: Bearer cal_wrong')
[[ "$CODE" == 401 ]] && pass "bad key rejected (401)" || fail "auth: $CODE"

echo "anthropic messages api"
msgs() { curl -s -D "$WORK/h" "http://127.0.0.1:$DP/v1/messages" -H "x-api-key: ${2:-$KEY}" -H 'anthropic-version: 2023-06-01' -H 'content-type: application/json' -d "$1"; }
OUT=$(msgs "{\"model\":\"ext/mock\",\"max_tokens\":64,\"system\":[{\"type\":\"text\",\"text\":\"Be brief.\"}],\"messages\":[{\"role\":\"user\",\"content\":\"$PII\"}]}")
python3 -c 'import sys,json;m=json.loads(sys.argv[1]);assert m["type"]=="message" and m["content"][0]["text"]==sys.argv[2] and m["usage"]["output_tokens"]==7,m' "$OUT" "You said: $PII" \
  && pass "/v1/messages on an OpenAI-compatible model: translated + rehydrated" || fail "messages: $OUT"
tail -1 "$MOCK_LOG" | python3 -c 'import sys,json;l=json.load(sys.stdin);b=l["body"];assert l["path"].endswith("/chat/completions") and b["messages"][0]=={"role":"system","content":"Be brief."} and "jane.doe@acme.com" not in json.dumps(b),l' \
  && pass "anthropic → OpenAI translation; upstream saw surrogates only" || fail "messages upstream body"
OUT=$(msgs "{\"model\":\"ext/mock\",\"max_tokens\":64,\"stream\":true,\"messages\":[{\"role\":\"user\",\"content\":\"$PII\"}]}")
python3 -c '
import sys,json
evs=[json.loads(l[6:]) for l in sys.argv[1].splitlines() if l.startswith("data: ")]
t=[e["type"] for e in evs]
text="".join(e["delta"].get("text","") for e in evs if e["type"]=="content_block_delta")
assert t[0]=="message_start" and t[-2:]==["message_delta","message_stop"] and "content_block_start" in t,t
assert text==sys.argv[2],text
assert evs[-2]["usage"]["output_tokens"]==7,evs[-2]' "$OUT" "You said: $PII" && pass "/v1/messages streaming: Anthropic events, rehydrated" || fail "messages stream: $OUT"
OUT=$(msgs "{\"model\":\"anthropic/mock\",\"max_tokens\":64,\"system\":[{\"type\":\"text\",\"text\":\"Long shared context\",\"cache_control\":{\"type\":\"ephemeral\"}}],\"messages\":[{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"$PII\",\"cache_control\":{\"type\":\"ephemeral\"}}]}]}")
python3 -c 'import sys,json;m=json.loads(sys.argv[1]);assert m["content"][0]["text"]==sys.argv[2] and m["model"]=="anthropic/mock",m' "$OUT" "You said: $PII" \
  && pass "native Anthropic passthrough: response rehydrated" || fail "native: $OUT"
tail -1 "$MOCK_LOG" | python3 -c 'import sys,json;l=json.load(sys.stdin);b=l["body"];assert l["path"].endswith("/messages") and l["x_api_key"]=="sk-ant-smoke-5678" and l["auth"] is None and b["model"]=="claude-mock" and b["system"][0]["cache_control"]=={"type":"ephemeral"} and b["messages"][0]["content"][0]["cache_control"]=={"type":"ephemeral"} and "jane.doe@acme.com" not in json.dumps(b),l' \
  && pass "native passthrough: cache_control kept, BYOK x-api-key, PII protected" || fail "native upstream: $(tail -1 "$MOCK_LOG")"
OUT=$(chat '{"model":"anthropic/mock","messages":[{"role":"user","content":"hello claude"}]}')
python3 -c 'import sys,json;m=json.loads(sys.argv[1]);assert m["choices"][0]["message"]["content"]=="You said: hello claude",m' "$OUT" \
  && pass "OpenAI client → Anthropic provider (translated both ways)" || fail "openai→anthropic: $OUT"
CODE=$(curl -s -o "$WORK/b" -w '%{http_code}' "http://127.0.0.1:$DP/v1/messages" -H 'x-api-key: cal_wrong' -H 'content-type: application/json' -d '{"model":"ext/mock","max_tokens":5,"messages":[{"role":"user","content":"x"}]}')
[[ "$CODE" == 401 ]] && grep -q '"authentication_error"' "$WORK/b" && pass "Anthropic-shaped errors on /v1/messages" || fail "anthropic error: $CODE $(cat "$WORK/b")"

echo "rate limits"
REQ='{"model":"local/mock","messages":[{"role":"user","content":"ping"}]}'
chat "$REQ" "$TKEY" >/dev/null; chat "$REQ" "$TKEY" >/dev/null
CODE=$(curl -s -D "$WORK/h" -o "$WORK/b" -w '%{http_code}' "http://127.0.0.1:$DP/v1/chat/completions" -H "authorization: Bearer $TKEY" -H 'content-type: application/json' -d "$REQ")
[[ "$CODE" == 429 ]] && grep -qi '^retry-after: [0-9]' "$WORK/h" && grep -q '"rate_limited"' "$WORK/b" \
  && pass "requests_per_minute exceeded → 429 + retry-after (OpenAI shape)" || fail "429: $CODE $(cat "$WORK/b")"
CODE=$(curl -s -o "$WORK/b" -w '%{http_code}' "http://127.0.0.1:$DP/v1/messages" -H "x-api-key: $TKEY" -H 'content-type: application/json' -d '{"model":"local/mock","max_tokens":5,"messages":[{"role":"user","content":"ping"}]}')
[[ "$CODE" == 429 ]] && grep -q '"rate_limit_error"' "$WORK/b" && pass "429 in Anthropic shape on /v1/messages" || fail "anthropic 429: $CODE $(cat "$WORK/b")"
chat "$REQ" >/dev/null; grep -qi '^HTTP/1.1 200' "$WORK/h" && pass "other tenants unaffected" || fail "noisy neighbour"

if [[ -n "${CALIBAN_PII_NER_DIR:-}" ]]; then
  echo "PII NER (L1 model)"
  NAMES='Please email Sarah Johnson at Globex Corporation in Denver about the renewal'
  OUT=$(chat "{\"model\":\"ext/mock\",\"messages\":[{\"role\":\"user\",\"content\":\"$NAMES\"}]}")
  tail -1 "$MOCK_LOG" | grep -qE 'Sarah Johnson|Globex Corporation|Denver' && fail "external model received names" || pass "names/orgs/places pseudonymized before external model"
  grep -q "You said: $NAMES" <<<"$OUT" && pass "names restored in the response" || fail "ner rehydration: $OUT"
fi

echo "open models (shared on-prem pool, Qwen3-style)"
OUT=$(chat '{"model":"local/qwen3-8b","messages":[{"role":"user","content":"hi"}]}')
python3 -c 'import sys,json;m=json.loads(sys.argv[1])["choices"][0]["message"];assert m["content"]=="You said: hi" and m["reasoning_content"]=="Let me think about it.",m' "$OUT" \
  && pass "inline <think> moved to reasoning_content" || fail "think split: $OUT"
tail -1 "$MOCK_LOG" | python3 -c 'import sys,json;b=json.load(sys.stdin)["body"];assert len(b["cache_salt"])==32,b' && pass "per-tenant cache_salt sent to shared pool" || fail "cache_salt"
OUT=$(chat '{"model":"local/qwen3-8b","stream":true,"messages":[{"role":"user","content":"hello stream"}]}')
python3 -c '
import sys,json
r=c=""
for l in sys.argv[1].splitlines():
    if l.startswith("data: {"):
        for ch in json.loads(l[6:]).get("choices",[]):
            d=ch.get("delta",{}); r+=d.get("reasoning_content") or ""; c+=d.get("content") or ""
assert (r,c)==("Let me think about it.","You said: hello stream"),(r,c)' "$OUT" && pass "streaming: <think> split across chunks" || fail "stream think: $OUT"
OUT=$(chat '{"model":"local/qwen3-8b","caliban":{"reasoning":"off"},"messages":[{"role":"user","content":"quick"}]}')
tail -1 "$MOCK_LOG" | grep -q '"enable_thinking": false' && grep -q '"content": *"You said: quick"' <<<"$(python3 -m json.tool <<<"$OUT")" \
  && pass "reasoning off → enable_thinking=false" || fail "thinking toggle: $OUT"

echo "control plane → data plane"
adm() { curl -s "http://127.0.0.1:$CP/api/v1$1" -H "authorization: Bearer $CALIBAN_ADMIN_TOKEN" -H 'content-type: application/json' "${@:2}"; }
adm /tenants -d '{"name":"Globex"}' >/dev/null
NEWKEY=$(adm /tenants/globex/api-keys -d '{"name":"smoke"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["key"])')
adm /tenants/globex/provider-keys -d "{\"kind\":\"openai_compatible\",\"label\":\"mockext\",\"base_url\":\"http://127.0.0.1:$MOCK_PORT/v1\",\"api_key\":\"sk-byok-globex-1234\",\"trust_tier\":\"t2_contracted\"}" | grep -q '"last4":"1234"' \
  && pass "BYOK key stored sealed (last4 only)" || fail "byok create"
OUT=$(chat '{"model":"caliban/auto","messages":[{"role":"user","content":"hello there"}]}' "$NEWKEY")
grep -q 'You said: hello there' <<<"$OUT" && pass "new tenant key + auto-route works" || fail "new tenant: $OUT"
tail -1 "$MOCK_LOG" | grep -q '"auth": "Bearer sk-byok-globex-1234"' && pass "tenant's own BYOK credential used upstream" || fail "byok upstream auth"
D=$(adm /providers/qwen-pool/discover -X POST)
python3 -c 'import sys,json;d=json.loads(sys.argv[1]);s={m["upstream_model"]:m for m in d["suggested"]};assert "Qwen/Qwen3-8B" not in s and s["Qwen/Qwen3-Embedding-0.6B"]["kind"]=="embedding",d' "$D" \
  && pass "discovery lists served models, suggests only new ones" || fail "discover: $D"
EMB=$(python3 -c 'import sys,json;d=json.loads(sys.argv[1]);print(json.dumps([m for m in d["suggested"] if m["kind"]=="embedding"][0]))' "$D")
adm /models -d "$EMB" | grep -q '"local/qwen3-embedding-0.6b"' && pass "suggested embedding model registered at runtime" || fail "register model"
OUT=$(curl -s "http://127.0.0.1:$DP/v1/embeddings" -H "authorization: Bearer $KEY" -H 'content-type: application/json' -d '{"model":"local/qwen3-embedding-0.6b","input":["a","b"]}')
python3 -c 'import sys,json;d=json.loads(sys.argv[1]);assert len(d["data"])==2 and d["model"]=="local/qwen3-embedding-0.6b",d' "$OUT" && pass "/v1/embeddings via shared pool" || fail "embeddings: $OUT"
OUT=$(curl -s "http://127.0.0.1:$DP/v1/rerank" -H "authorization: Bearer $KEY" -H 'content-type: application/json' -d '{"model":"local/rerank","query":"red apple","documents":["blue sky","red apple pie","green apple"],"top_n":2,"return_documents":true}')
python3 -c 'import sys,json;r=json.loads(sys.argv[1])["results"];assert [x["index"] for x in r]==[1,2] and r[0]["document"]["text"]=="red apple pie",r' "$OUT" && pass "/v1/rerank sorted, top_n, original documents" || fail "rerank: $OUT"
adm "/usage?tenant_id=acme" | python3 -c 'import sys,json;t=json.load(sys.stdin)["totals"];assert t["requests"]>=5 and t["cache_hits"]>=1,t' && pass "usage metered" || fail "usage"
echo "all smoke checks passed"
