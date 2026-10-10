#!/usr/bin/env python3
"""Split mode checks across the gateway (control plane plus its own router) and N routers (stdlib).

Mock upstreams run on the loadgen (bench `mock-upstream`): :9000 (instant), :9001 (--latency-ms 2000)
and :8003 (--record, for the BYOK check; the testbed security group admits 8000-8003 and 9000-9001).

  split.py setup  --admin TOKEN > split.json   providers, models, tenants, keys, BYOK key
  split.py versions                            config (snapshot) version served by every node
  split.py quota  --n 40                       requests_per_minute shared across routers
                                               (needs [limits.tenants.split-quota] requests_per_minute = 20)
  split.py idem                                Idempotency-Key replay across routers, 409, 422
  split.py byok                                the BYOK key opened by every node (the mock records the credential)
  split.py serve                               one request per node (fail-static checks)

Addresses: GATEWAY_IP, LOADGEN_IP and ROUTER_IPS (space separated) from the environment.
"""
import argparse, http.client, json, os, sys, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tbenv import ip, ips  # noqa: E402

GW = ip("GATEWAY_IP")
LG = ip("LOADGEN_IP")
ROUTERS = ips("ROUTER_IPS")
BYOK_KEY = "sk-byok-testbed-7a1c"  # a fake upstream credential; only the mock sees it
BYOK_PORT = 8003


def call(host, port, method, path, body=None, token=None, headers=None, timeout=60):
    c = http.client.HTTPConnection(host, port, timeout=timeout)
    h = {"Content-Type": "application/json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    h.update(headers or {})
    c.request(method, path, body=json.dumps(body) if body is not None else None, headers=h)
    r = c.getresponse()
    data = r.read()
    try:
        j = json.loads(data)
    except ValueError:
        j = data.decode(errors="replace")
    return r.status, {k.lower(): v for k, v in r.getheaders()}, j


def chat(host, key, model, prompt, idem=None, timeout=60):
    h = {"Idempotency-Key": idem} if idem else {}
    return call(host, 8080, "POST", "/v1/chat/completions",
                {"model": model, "messages": [{"role": "user", "content": prompt}], "max_tokens": 16}, key, h, timeout)


def setup(a):
    adm = a.admin
    out = {}
    for pid, port in (("benchmock", 9000), ("slowmock", 9001)):
        print(pid, call(GW, 8081, "POST", "/api/v1/providers", {"id": pid, "kind": "openai_compatible", "base_url": f"http://{LG}:{port}/v1", "trust_tier": "t0_sovereign"}, adm)[0], file=sys.stderr)
    for mid, pid in (("bench/mock", "benchmock"), ("bench/slow", "slowmock")):
        print(mid, call(GW, 8081, "POST", "/api/v1/models", {"id": mid, "provider": pid, "upstream_model": "mock", "kind": "chat", "trust_tier": "t0_sovereign"}, adm)[0], file=sys.stderr)
    for name in ("split-quota", "split-idem", "split-byok"):
        s, _, t = call(GW, 8081, "POST", "/api/v1/tenants", {"name": name, "pii_default": "off"}, adm)
        tid = t["id"]
        s, _, k = call(GW, 8081, "POST", f"/api/v1/tenants/{tid}/api-keys", {"name": "split"}, adm)
        model = "bench/mock"
        if name == "split-byok":
            # BYOK: sealed under the tenant's data key; routers open it from the signed snapshot.
            s, _, pk = call(GW, 8081, "POST", f"/api/v1/tenants/{tid}/provider-keys",
                            {"kind": "openai_compatible", "label": "byok mock", "provider_id": "byokmock",
                             "base_url": f"http://{LG}:{BYOK_PORT}/v1", "api_key": BYOK_KEY, "trust_tier": "t0_sovereign"}, adm)
            print("provider key", s, file=sys.stderr)
            model = "byok/mock"
            s, _, m = call(GW, 8081, "POST", "/api/v1/models", {"id": model, "provider": "byokmock", "upstream_model": "mock", "kind": "chat", "trust_tier": "t0_sovereign"}, adm)
            print("byok model", s, file=sys.stderr)
        s2, _, r = call(GW, 8081, "PUT", f"/api/v1/tenants/{tid}/routes", {"routes": [{"intent": "default", "models": [model]}]}, adm)
        out[name] = {"tenant": tid, "key": k["key"], "model": model}
        print(name, tid, "routes", s2, file=sys.stderr)
    print(json.dumps(out))


def nodes():
    return [("gateway", GW)] + [(f"router-{i + 1}", ip) for i, ip in enumerate(ROUTERS)]


def versions(a):
    for name, node in nodes():
        try:
            s, h, j = call(node, 8080, "GET", "/healthz", timeout=5)
            print(name, s, j.get("config_version") if isinstance(j, dict) else j, (j.get("quota") or {}).get("store") if isinstance(j, dict) else "", (j.get("quota") or {}).get("state") if isinstance(j, dict) else "")
        except Exception as e:  # noqa: BLE001
            print(name, "unreachable", e)


def quota(a):
    st = json.load(open(a.state))["split-quota"]
    res = {}
    t0 = time.time()
    for i in range(a.n):
        name, ip = nodes()[1 + i % len(ROUTERS)]
        s, h, _ = chat(node, st["key"], st["model"], f"quota probe {i}")
        res.setdefault(name, {}).setdefault(s, 0)
        res[name][s] += 1
    ok = sum(v.get(200, 0) for v in res.values())
    print(json.dumps({"elapsed_s": round(time.time() - t0, 2), "per_router": res, "allowed_total": ok, "sent": a.n}))


def idem(a):
    st = json.load(open(a.state))["split-idem"]
    A, B = ROUTERS[0], ROUTERS[1]
    k1 = f"tb-idem-{int(time.time())}"
    s1, h1, j1 = chat(A, st["key"], "bench/mock", "idempotent hello", k1)
    s2, h2, j2 = chat(B, st["key"], "bench/mock", "idempotent hello", k1)
    rep = {"first_A": [s1, h1.get("idempotent-replayed"), h1.get("x-caliban-request-id")],
           "same_key_B": [s2, h2.get("idempotent-replayed"), h2.get("x-caliban-request-id")],
           "same_body": j1 == j2}
    s3, h3, j3 = chat(B, st["key"], "bench/mock", "a different body", k1)
    rep["different_body_B"] = [s3, (j3.get("error") or {}).get("code") if isinstance(j3, dict) else j3]
    # Concurrent duplicate: the first (slow upstream, 2 s) still runs on A when B sees the key.
    k2 = k1 + "-slow"
    box = {}
    th = threading.Thread(target=lambda: box.update(a=chat(A, st["key"], "bench/slow", "slow one", k2)))
    th.start()
    time.sleep(0.5)
    s4, h4, j4 = chat(B, st["key"], "bench/slow", "slow one", k2)
    rep["concurrent_dup_B"] = [s4, (j4.get("error") or {}).get("code") if isinstance(j4, dict) else j4, h4.get("retry-after")]
    th.join()
    sa = box["a"]
    rep["slow_first_A"] = [sa[0], sa[1].get("x-caliban-request-id")]
    s5, h5, j5 = chat(B, st["key"], "bench/slow", "slow one", k2)
    rep["after_completion_B"] = [s5, h5.get("idempotent-replayed"), h5.get("x-caliban-request-id")]
    t0 = time.time()
    rep["replay_ms"] = None
    s6, h6, _ = chat(ROUTERS[0], st["key"], "bench/slow", "slow one", k2)
    rep["replay_ms"] = round((time.time() - t0) * 1000, 1)
    rep["replay_A_again"] = [s6, h6.get("idempotent-replayed")]
    print(json.dumps(rep, indent=1))


def byok(a):
    st = json.load(open(a.state))["split-byok"]
    out = {}
    for name, node in nodes():
        try:
            s, h, j = chat(node, st["key"], st["model"], f"byok via {name} {time.time()}", timeout=10)
        except OSError as e:
            out[name] = f"unreachable: {type(e).__name__}"
            continue
        out[name] = [s, (j.get("error") or {}).get("message", "")[:120] if isinstance(j, dict) and s != 200 else "ok"]
    s, _, log = call(LG, BYOK_PORT, "GET", "/__mock/log")
    auths = []
    if isinstance(log, (list, dict)):
        entries = log if isinstance(log, list) else (log.get("requests") or log.get("log") or [])
        auths = sorted({str(e.get("auth") or e.get("x_api_key")) for e in entries[-10:] if isinstance(e, dict)})
    out["upstream_saw"] = [x.replace(BYOK_KEY, "<the BYOK key>") for x in auths]
    print(json.dumps(out))


def serve(a):
    st = json.load(open(a.state))["split-idem"]
    out = {}
    for name, node in nodes():
        try:
            s, h, j = chat(node, st["key"], "bench/mock", f"serve {name} {time.time()}", timeout=5)
            out[name] = s
        except Exception as e:  # noqa: BLE001
            out[name] = f"unreachable: {type(e).__name__}"
    print(json.dumps(out))


ap = argparse.ArgumentParser()
ap.add_argument("cmd", choices=["setup", "versions", "quota", "idem", "byok", "serve"])
ap.add_argument("--admin")
ap.add_argument("--state", default="split.json")
ap.add_argument("--n", type=int, default=40)
a = ap.parse_args()
globals()[a.cmd](a)
