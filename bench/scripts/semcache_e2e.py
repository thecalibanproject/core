#!/usr/bin/env python3
"""Semantic cache end to end through Caliban (stdlib only).

  semcache_e2e.py setup  --gw http://$GATEWAY_IP --admin TOKEN --mock http://$LOADGEN_IP:9000 --suffix r1 > keys.json
  semcache_e2e.py hits   --gw http://$GATEWAY_IP --keys keys.json --model local/qwen3.8-27b --out hits.json
  semcache_e2e.py misslat --gw http://$GATEWAY_IP --keys keys.json --n 200 --out misslat.json
"""
import argparse, http.client, json, os, random, sys, time
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from semcache_pairs import PARAPHRASES, NEAR_MISSES  # noqa: E402
from tbenv import env_default  # noqa: E402


def call(base, method, path, body=None, token=None, timeout=120):
    u = urlparse(base)
    c = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
    h = {"Content-Type": "application/json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    c.request(method, path, body=json.dumps(body) if body is not None else None, headers=h)
    r = c.getresponse()
    data = r.read()
    c.close()
    try:
        j = json.loads(data)
    except ValueError:
        j = data.decode(errors="replace")
    return r.status, dict((k.lower(), v) for k, v in r.getheaders()), j


def setup(a):
    cp = a.gw + ":8081"
    out = {}
    # Mock provider + model (shared), for the miss-latency test.
    print(call(cp, "POST", "/api/v1/providers", {"id": "benchmock", "kind": "openai_compatible", "base_url": f"{a.mock}/v1", "trust_tier": "t0_sovereign"}, a.admin)[:1], file=sys.stderr)
    print(call(cp, "POST", "/api/v1/models", {"id": "bench/mock", "provider": "benchmock", "upstream_model": "mock", "kind": "chat", "trust_tier": "t0_sovereign"}, a.admin)[:1], file=sys.stderr)
    for name, sem in ((f"sem-on-{a.suffix}", "on"), (f"sem-off-{a.suffix}", "off")):
        s, _, t = call(cp, "POST", "/api/v1/tenants", {"name": name, "pii_default": "off", "semantic_cache": sem}, a.admin)
        print(name, s, t if s >= 300 else t.get("id"), file=sys.stderr)
        tid = t["id"] if isinstance(t, dict) and "id" in t else name
        s, _, k = call(cp, "POST", f"/api/v1/tenants/{tid}/api-keys", {"name": "bench"}, a.admin)
        s2, _, r = call(cp, "PUT", f"/api/v1/tenants/{tid}/routes", {"routes": [{"intent": "default", "models": ["local/qwen3.8-27b"]}]}, a.admin)
        print("  key", s, "routes", s2, file=sys.stderr)
        out[sem] = {"tenant": tid, "key": k["key"]}
    print(json.dumps(out))


def chat(gw, key, model, prompt, max_tokens=64, temperature=0):
    t0 = time.perf_counter()
    s, h, j = call(gw + ":8080", "POST", "/v1/chat/completions",
                   {"model": model, "messages": [{"role": "user", "content": prompt}], "max_tokens": max_tokens,
                    "temperature": temperature, "chat_template_kwargs": {"enable_thinking": False}}, key)
    dt = (time.perf_counter() - t0) * 1000
    text = ""
    if isinstance(j, dict) and j.get("choices"):
        text = j["choices"][0]["message"].get("content") or ""
    return s, h.get("x-caliban-cache"), h.get("x-caliban-cache-tier"), dt, text


def hits(a):
    keys = json.load(open(a.keys))
    key = keys["on"]["key"]
    seeds = sorted({p[0] for p in PARAPHRASES} | {p[0] for p in NEAR_MISSES})
    seeded = {}
    for p in seeds:
        s, c, tier, dt, text = chat(a.gw, key, a.model, p)
        seeded[p] = {"status": s, "cache": c, "ms": dt, "answer": text[:200]}
    time.sleep(3)  # inserts run in the background after the response
    res = {"paraphrase": [], "near_miss": []}
    for kind, pairs in (("paraphrase", PARAPHRASES), ("near_miss", NEAR_MISSES)):
        for x, y in pairs:
            s, c, tier, dt, text = chat(a.gw, key, a.model, y)
            res[kind].append({"seed": x, "probe": y, "status": s, "cache": c, "tier": tier, "ms": dt, "answer": text[:200], "seed_answer": seeded[x]["answer"]})
    for kind in res:
        n = len(res[kind])
        h = sum(1 for r in res[kind] if r["cache"] == "hit" and r["tier"] == "semantic")
        print(f"{kind}: {h}/{n} semantic hits", file=sys.stderr)
    for r in res["near_miss"]:
        if r["cache"] == "hit":
            print(f"  FALSE HIT: {r['seed']} | {r['probe']}", file=sys.stderr)
    for r in res["paraphrase"]:
        if r["cache"] != "hit":
            print(f"  missed paraphrase: {r['seed']} | {r['probe']}", file=sys.stderr)
    res["seeded"] = seeded
    json.dump(res, open(a.out, "w"), indent=1)


WORDS = ("alpha amber anchor apple arch atlas autumn badge bamboo banner basil beacon birch bison blossom bolt bramble breeze "
         "bridge bronze cabin cactus canyon carbon castle cedar chalk cherry cinder citrus cliff clover cobalt comet copper coral "
         "crane crystal dagger delta desert dune eagle ember falcon fern fjord forest fossil garnet geyser glacier granite harbor "
         "hazel helium heron horizon iris ivory jade jasmine kelp lagoon lantern lava lemon lilac linen lotus magnet maple marble "
         "meadow mercury mesa mint moss nectar nickel oasis olive onyx orchid otter pebble pepper pine plume prism quartz quill "
         "raven reef ridge river ruby saffron sage sapphire shale sierra silver slate spruce summit thistle thunder topaz tulip "
         "tundra velvet violet walnut willow zephyr").split()
TOPICS = ["history of", "how to clean", "price of", "recipe with", "safety rules for", "poem about", "maintenance of", "origin of the name",
          "tax treatment of", "best season to visit", "chemical formula of", "migration pattern of", "insurance for", "legal status of"]


def misslat(a):
    keys = json.load(open(a.keys))
    rnd = random.Random(7)
    lat = {"on": [], "off": []}
    cache = {"on": {}, "off": {}}
    # warm up connections and the embedder
    for side in ("on", "off"):
        for i in range(10):
            chat(a.gw, keys[side]["key"], "bench/mock", f"warm up {side} {i} {rnd.random()}")
    for i in range(a.n):
        prompt = f"Tell me about the {rnd.choice(TOPICS)} {rnd.choice(WORDS)} {rnd.choice(WORDS)} number {rnd.randint(1, 10**6)} in {rnd.choice(WORDS)} county"
        for side in (("on", "off") if i % 2 == 0 else ("off", "on")):
            s, c, tier, dt, _ = chat(a.gw, keys[side]["key"], "bench/mock", prompt + f" ({side})")
            lat[side].append(dt)
            cache[side][f"{c}/{tier}"] = cache[side].get(f"{c}/{tier}", 0) + 1

    def pct(xs, p):
        xs = sorted(xs)
        k = (len(xs) - 1) * p
        f = int(k)
        return xs[f] + (xs[min(f + 1, len(xs) - 1)] - xs[f]) * (k - f)
    out = {}
    for side in lat:
        out[side] = {q: pct(lat[side], v) for q, v in (("p50", .5), ("p90", .9), ("p99", .99))}
        out[side]["cache"] = cache[side]
        print(f"semantic {side}: p50 {out[side]['p50']:.2f} ms p90 {out[side]['p90']:.2f} p99 {out[side]['p99']:.2f} {cache[side]}", file=sys.stderr)
    out["added_p50"] = out["on"]["p50"] - out["off"]["p50"]
    out["added_p90"] = out["on"]["p90"] - out["off"]["p90"]
    print(f"added on a miss: p50 {out['added_p50']:.2f} ms, p90 {out['added_p90']:.2f} ms", file=sys.stderr)
    json.dump(out, open(a.out, "w"), indent=1)


ap = argparse.ArgumentParser()
ap.add_argument("cmd", choices=["setup", "hits", "misslat"])
ap.add_argument("--gw", default=env_default("GATEWAY_IP", "http://{}"), help="default http://$GATEWAY_IP")
ap.add_argument("--admin")
ap.add_argument("--mock", default=env_default("LOADGEN_IP", "http://{}:9000"), help="default http://$LOADGEN_IP:9000")
ap.add_argument("--suffix", default="r1")
ap.add_argument("--keys")
ap.add_argument("--model", default="local/qwen3.8-27b")
ap.add_argument("--n", type=int, default=200)
ap.add_argument("--out")
a = ap.parse_args()
{"setup": setup, "hits": hits, "misslat": misslat}[a.cmd](a)
