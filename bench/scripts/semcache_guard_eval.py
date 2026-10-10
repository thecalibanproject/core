#!/usr/bin/env python3
"""Offline semantic-cache check over the hand-written pairs (stdlib only, Python 3.9+).

Embeds the 36 paraphrase and 38 near-miss pairs of semcache_pairs.py with and without the
default cache query prefix, takes the guard verdict of every pair from core's guard_pairs test
(`cargo test -p caliban-cache --test guard_pairs`), and counts a pair as a hit when the guards let
it through and its cosine is at or above the threshold (the entry's starting threshold; learning
and verification are not simulated).

  semcache_guard_eval.py --embed http://127.0.0.1:58080,Qwen/Qwen3-Embedding-0.6B [--core ../..]

The embedder is any OpenAI-compatible /v1/embeddings endpoint (TEI, vLLM, or Caliban with
",KEY" appended). On CPU, TEI 1.9.4 with Qwen3-Embedding-0.6B reproduces the AWS run's 24 of 36
and 0 of 38 for the guards of that run (prefix, 0.91).
"""
import argparse, http.client, json, math, os, re, subprocess, sys
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from semcache_pairs import PARAPHRASES, NEAR_MISSES  # noqa: E402

PREFIX = "Instruct: Given a user question, retrieve questions that ask exactly the same thing\nQuery: "


def embed(target, texts):
    url, model, *key = target.split(",")
    u = urlparse(url)
    c = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=300)
    h = {"Content-Type": "application/json"}
    if key:
        h["Authorization"] = f"Bearer {key[0]}"
    out = []
    for i in range(0, len(texts), 16):
        c.request("POST", (u.path.rstrip("/") or "") + "/v1/embeddings", json.dumps({"model": model, "input": texts[i:i + 16]}), h)
        r = c.getresponse()
        body = r.read()
        if r.status != 200:
            raise SystemExit(f"embeddings: HTTP {r.status}: {body[:300]!r}")
        data = sorted(json.loads(body)["data"], key=lambda x: x.get("index", 0))
        for d in data:
            n = math.sqrt(sum(x * x for x in d["embedding"])) or 1.0
            out.append([x / n for x in d["embedding"]])
    return out


def guard_verdicts(core):
    run = subprocess.run(["cargo", "test", "-q", "-p", "caliban-cache", "--test", "guard_pairs", "--", "--nocapture"],
                         cwd=core, capture_output=True, text=True, check=True)
    v = {}
    for line in run.stdout.splitlines():
        m = re.match(r'^(paraphrase|near-miss)\s+(PASS|BLOCK)\s+"(.*)" / "(.*)"$', line.strip())
        if m:
            v[(m.group(3), m.group(4))] = m.group(2) == "PASS"
    return v


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--embed", required=True, help="URL,MODEL[,KEY] of an OpenAI-compatible embeddings endpoint")
    ap.add_argument("--core", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
    a = ap.parse_args()
    g = guard_verdicts(a.core)
    for label, prefix in (("no prefix", ""), ("default prefix", PREFIX)):
        sims = {}
        for name, pairs in (("paraphrase", PARAPHRASES), ("near_miss", NEAR_MISSES)):
            vs = embed(a.embed, [prefix + x for p in pairs for x in p])
            sims[name] = [(p, sum(x * y for x, y in zip(vs[2 * i], vs[2 * i + 1]))) for i, p in enumerate(pairs)]
        for th in (0.95, 0.93, 0.92, 0.91, 0.90):
            hit = sum(s >= th and g[p] for p, s in sims["paraphrase"])
            false = [(p, s) for p, s in sims["near_miss"] if s >= th and g[p]]
            print(f"{label:15s} threshold {th:.2f}: {hit:2d}/36 paraphrases hit, {len(false)}/38 near-misses hit")
            for p, s in false:
                print(f"    false hit {s:.3f}: {p[0]} | {p[1]}")
        closest = max((s for p, s in sims["near_miss"] if g[p]), default=float("nan"))
        print(f"{label:15s} closest near-miss the guards let through: cosine {closest:.4f}")


if __name__ == "__main__":
    main()
