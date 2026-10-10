#!/usr/bin/env python3
"""Cache-hit billing for caliban/auto, end to end (stdlib only).

  bill.py --gw http://$GATEWAY_IP --admin TOKEN --price-in 3 --price-out 12 --fraction 0.2 --out bill.json

A fresh tenant (semantic cache on, PII off) sends through caliban/auto: a miss, the identical
request again (T1 exact hit), then a paraphrase (T2 semantic hit). Checks every usage event and
the totals of GET /api/v1/usage against the pricing rules (README "Pricing and metering of cache
hits"): miss billed at the flat price; hits cost 0, billed fraction x flat price of the cached
answer's tokens, saved the rest.
"""
import argparse, json, sys, time
sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.abspath(__file__)))
from tb_admin import call, INTENTS  # noqa: E402
from tbenv import env_default  # noqa: E402

PAIRS = [("Explain what a mutex is.", "Can you explain what a mutex is?"),
         ("Recommend a good book about distributed systems.", "Can you suggest a good book on distributed systems?"),
         ("What do people use Kubernetes for?", "What is Kubernetes used for?")]

checks = []


def check(name, ok, detail=""):
    checks.append({"check": name, "ok": bool(ok), "detail": detail})
    print(("PASS " if ok else "FAIL ") + name + (f": {detail}" if detail else ""), file=sys.stderr)


def close(a, b, eps=1e-9):
    return a is not None and b is not None and abs(a - b) <= eps * max(1.0, abs(b))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gw", default=env_default("GATEWAY_IP", "http://{}"), help="default http://$GATEWAY_IP")
    ap.add_argument("--admin", required=True)
    ap.add_argument("--price-in", type=float, default=3.0)
    ap.add_argument("--price-out", type=float, default=12.0)
    ap.add_argument("--fraction", type=float, default=0.2)
    ap.add_argument("--model", default="local/qwen3.8-27b")
    ap.add_argument("--out")
    a = ap.parse_args()
    cp, dp = a.gw + ":8081", a.gw + ":8080"
    s, t = call(cp, "POST", "/api/v1/tenants", {"name": f"bill-{int(time.time())}", "pii_default": "off", "semantic_cache": "on"}, a.admin)
    tid = t["id"]
    s, k = call(cp, "POST", f"/api/v1/tenants/{tid}/api-keys", {"name": "bill"}, a.admin)
    key = k["key"]
    call(cp, "PUT", f"/api/v1/tenants/{tid}/routes", {"routes": [{"intent": i, "models": [a.model]} for i in INTENTS]}, a.admin)

    def chat(prompt):
        from urllib.parse import urlparse
        import http.client
        u = urlparse(dp)
        c = http.client.HTTPConnection(u.hostname, u.port, timeout=120)
        body = {"model": "caliban/auto", "messages": [{"role": "user", "content": prompt}], "max_tokens": 48,
                "temperature": 0, "chat_template_kwargs": {"enable_thinking": False}}
        t0 = time.perf_counter()
        c.request("POST", "/v1/chat/completions", json.dumps(body), {"Content-Type": "application/json", "Authorization": f"Bearer {key}"})
        r = c.getresponse()
        j = json.loads(r.read())
        h = {k.lower(): v for k, v in r.getheaders()}
        return {"status": r.status, "ms": (time.perf_counter() - t0) * 1000, "cache": h.get("x-caliban-cache"), "tier": h.get("x-caliban-cache-tier"),
                "cost_header": h.get("x-caliban-cost-usd"), "intent": h.get("x-caliban-intent"), "routed": h.get("x-caliban-routed-model"),
                "request_id": h.get("x-caliban-request-id"), "usage": j.get("usage")}

    seq = []
    for seed, para in PAIRS:
        m = chat(seed)
        time.sleep(3)  # the semantic insert runs after the response
        e = chat(seed)
        p = chat(para)
        seq = [("miss", m), ("exact", e), ("semantic", p)]
        if p["tier"] == "semantic":
            break
        print(f"paraphrase did not hit semantically ({p['cache']}/{p['tier']}); next pair", file=sys.stderr)
    for kind, r in seq:
        print(kind, json.dumps(r), file=sys.stderr)
    m, e, p = (r for _, r in seq)
    check("first request is a miss", m["cache"] in (None, "miss"), str(m["cache"]))
    check("repeat is an exact (T1) hit", e["cache"] == "hit" and e["tier"] == "exact", f"{e['cache']}/{e['tier']}")
    check("paraphrase is a semantic (T2) hit", p["cache"] == "hit" and p["tier"] == "semantic", f"{p['cache']}/{p['tier']}")
    for kind, r in seq[1:]:
        check(f"{kind} hit: x-caliban-cost-usd is 0", r["cost_header"] is not None and float(r["cost_header"]) == 0.0, str(r["cost_header"]))

    s, u = call(cp, "GET", f"/api/v1/usage?tenant_id={tid}", None, a.admin)
    ev = {x.get("request_id"): x for x in u["events"]}
    flat = lambda pt, ct: (pt * a.price_in + ct * a.price_out) / 1e6
    em = ev.get(m["request_id"])
    pt, ct = em["prompt_tokens"], em["completion_tokens"]
    f_miss = flat(pt, ct)
    check("miss: flat_price_usd = flat price of its tokens", close(em.get("flat_price_usd"), f_miss), f"{em.get('flat_price_usd')} vs {f_miss} ({pt} in, {ct} out)")
    check("miss: billed_usd = flat price", close(em.get("billed_usd"), f_miss), str(em.get("billed_usd")))
    check("miss: routed_model_cost_usd = model's real cost (0 for this on-prem model)", close(em.get("routed_model_cost_usd"), 0.0), str(em.get("routed_model_cost_usd")))
    check("miss: no saved_usd", em.get("saved_usd") is None, str(em.get("saved_usd")))
    for kind, r in seq[1:]:
        x = ev.get(r["request_id"])
        if x is None:
            check(f"{kind}: usage event present", False, r["request_id"])
            continue
        # The hit is priced from the tokens stored with the cache entry (the original request's).
        fx = x.get("flat_price_usd")
        check(f"{kind}: cost_usd and routed_model_cost_usd are 0", close(x.get("cost_usd"), 0.0) and close(x.get("routed_model_cost_usd") or 0.0, 0.0),
              f"cost {x.get('cost_usd')} routed {x.get('routed_model_cost_usd')}")
        check(f"{kind}: no prompt or completion tokens metered", x["prompt_tokens"] == 0 and x["completion_tokens"] == 0, f"{x['prompt_tokens']}/{x['completion_tokens']}")
        check(f"{kind}: flat_price_usd = the cached answer's flat price", close(fx, f_miss), f"{fx} vs {f_miss}")
        check(f"{kind}: billed_usd = {a.fraction} x flat price", close(x.get("billed_usd"), a.fraction * f_miss), f"{x.get('billed_usd')} vs {a.fraction * f_miss}")
        check(f"{kind}: saved_usd = flat - billed", close(x.get("saved_usd"), (1 - a.fraction) * f_miss), str(x.get("saved_usd")))
        check(f"{kind}: cache_tier recorded", x.get("cache_tier") == kind, str(x.get("cache_tier")))
    tot = u["totals"]
    exp_billed = f_miss * (1 + 2 * a.fraction)
    check("totals: auto_requests 3, auto_cache_hits 2", tot.get("auto_requests") == 3 and tot.get("auto_cache_hits") == 2, f"{tot.get('auto_requests')}/{tot.get('auto_cache_hits')}")
    check("totals: semantic_cache_hits 1", tot.get("semantic_cache_hits") == 1, str(tot.get("semantic_cache_hits")))
    check("totals: flat_price_usd = 3 x flat", close(tot.get("flat_price_usd"), 3 * f_miss), f"{tot.get('flat_price_usd')}")
    check("totals: billed_usd = flat x (1 + 2 x fraction)", close(tot.get("billed_usd"), exp_billed), f"{tot.get('billed_usd')} vs {exp_billed}")
    check("totals: auto_saved_usd = saved_usd = 2 x (1 - fraction) x flat", close(tot.get("auto_saved_usd"), 2 * (1 - a.fraction) * f_miss) and close(tot.get("saved_usd"), 2 * (1 - a.fraction) * f_miss),
          f"{tot.get('auto_saved_usd')} / {tot.get('saved_usd')}")
    check("totals: routed_model_cost_usd 0, margin_usd = billed_usd", close(tot.get("routed_model_cost_usd"), 0.0) and close(tot.get("margin_usd"), exp_billed), f"{tot.get('routed_model_cost_usd')} / {tot.get('margin_usd')}")
    n = sum(c["ok"] for c in checks)
    print(f"{n}/{len(checks)} checks passed", file=sys.stderr)
    if a.out:
        json.dump({"tenant": tid, "sequence": seq, "events": [ev.get(r["request_id"]) for _, r in seq], "totals": tot, "checks": checks}, open(a.out, "w"), indent=1)


main()
