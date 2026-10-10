#!/usr/bin/env python3
"""Admin helpers for the testbed runs (stdlib only).

  tb_admin.py tenant --cp http://GW:8081 --admin TOKEN --name auto-bench --sem off --model local/qwen3.8-27b
      creates a tenant (PII off), an API key and a route for every built-in intent plus "default",
      all to --model; prints {"tenant": id, "key": key}.
"""
import argparse, http.client, json, sys
from urllib.parse import urlparse

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.abspath(__file__)))
from tbenv import env_default  # noqa: E402

INTENTS = ["analytics", "chat", "code", "extraction", "reasoning", "summarize", "translate", "default"]


def call(base, method, path, body=None, token=None, headers=None):
    u = urlparse(base)
    c = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=60)
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
    return r.status, j


def tenant(a):
    body = {"name": a.name, "pii_default": a.pii, "semantic_cache": a.sem}
    if a.fraction is not None:
        body["auto_cache_hit_fraction"] = a.fraction
    s, t = call(a.cp, "POST", "/api/v1/tenants", body, a.admin)
    if s >= 300:
        sys.exit(f"tenant: {s} {t}")
    tid = t["id"]
    s, k = call(a.cp, "POST", f"/api/v1/tenants/{tid}/api-keys", {"name": "bench"}, a.admin)
    if s >= 300:
        sys.exit(f"key: {s} {k}")
    s, r = call(a.cp, "PUT", f"/api/v1/tenants/{tid}/routes", {"routes": [{"intent": i, "models": [a.model]} for i in INTENTS]}, a.admin)
    if s >= 300:
        sys.exit(f"routes: {s} {r}")
    print(json.dumps({"tenant": tid, "key": k["key"]}))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["tenant"])
    ap.add_argument("--cp", default=env_default("GATEWAY_IP", "http://{}:8081"), help="default http://$GATEWAY_IP:8081")
    ap.add_argument("--admin")
    ap.add_argument("--name")
    ap.add_argument("--pii", default="off")
    ap.add_argument("--sem", default="off")
    ap.add_argument("--fraction", type=float)
    ap.add_argument("--model", default="local/qwen3.8-27b")
    a = ap.parse_args()
    {"tenant": tenant}[a.cmd](a)
