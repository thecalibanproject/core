#!/usr/bin/env python3
"""Embedding measurements (stdlib only, Python 3.9+).

  embed_tools.py latency --target direct=http://$GPU_IP:8001,Qwen/Qwen3-Embedding-0.6B \
                         --target caliban=http://$GATEWAY_IP:8080,local/qwen3-embedding-0.6b,KEY --n 300
  embed_tools.py pairs   --target direct=http://$GPU_IP:8001,Qwen/Qwen3-Embedding-0.6B --out pairs.json
  embed_tools.py knn     --target direct=... --dataset exemplars.default.json [--prefix '...'] --out knn.json
"""
import argparse, http.client, json, math, os, sys, time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from semcache_pairs import PARAPHRASES, NEAR_MISSES  # noqa: E402


def parse_target(s):
    name, _, rest = s.partition("=")
    parts = rest.split(",")
    u = urlparse(parts[0])
    return {"name": name, "host": u.hostname, "port": u.port or 80, "path": (u.path.rstrip("/") or "") + "/v1/embeddings",
            "model": parts[1], "key": parts[2] if len(parts) > 2 else None}


class Client:
    def __init__(self, t):
        self.t = t
        self.c = http.client.HTTPConnection(t["host"], t["port"], timeout=60)

    def embed(self, texts):
        h = {"Content-Type": "application/json"}
        if self.t["key"]:
            h["Authorization"] = f"Bearer {self.t['key']}"
        body = json.dumps({"model": self.t["model"], "input": texts})
        for attempt in range(2):
            try:
                self.c.request("POST", self.t["path"], body=body, headers=h)
                r = self.c.getresponse()
                data = r.read()
                break
            except (http.client.HTTPException, OSError):
                self.c.close()
                self.c = http.client.HTTPConnection(self.t["host"], self.t["port"], timeout=60)
                if attempt:
                    raise
        if r.status != 200:
            raise RuntimeError(f"HTTP {r.status}: {data[:300]!r}")
        d = json.loads(data)["data"]
        d.sort(key=lambda x: x.get("index", 0))
        return [x["embedding"] for x in d]

    def embed_many(self, texts, batch=32):
        out = []
        for i in range(0, len(texts), batch):
            out += self.embed(texts[i:i + batch])
        return out


def norm(v):
    n = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / n for x in v]


def cos(a, b):
    return sum(x * y for x, y in zip(a, b))


def pct(xs, p):
    xs = sorted(xs)
    if not xs:
        return float("nan")
    k = (len(xs) - 1) * p
    f = int(k)
    c = min(f + 1, len(xs) - 1)
    return xs[f] + (xs[c] - xs[f]) * (k - f)


def cmd_latency(args):
    res = {}
    texts = ["How do I reset my password?", "Summarise the quarterly sales report for the board in three bullet points."]
    for ts in args.target:
        t = parse_target(ts)
        for conc in [int(c) for c in args.concurrency.split(",")]:
            lat = []
            def worker(k):
                cl = Client(t)
                mine = []
                for i in range(args.n // conc):
                    q = f"{texts[i % 2]} (variant {args.tag}{k}-{i})"
                    t0 = time.perf_counter()
                    cl.embed([q])
                    mine.append((time.perf_counter() - t0) * 1000)
                return mine
            Client(t).embed(["warm up"] * 4)
            for _ in range(20):
                Client(t).embed(["warm up single"])
            t0 = time.perf_counter()
            with ThreadPoolExecutor(conc) as ex:
                for m in ex.map(worker, range(conc)):
                    lat += m
            wall = time.perf_counter() - t0
            r = {"p50": pct(lat, .5), "p90": pct(lat, .9), "p99": pct(lat, .99), "max": max(lat), "n": len(lat), "req_s": len(lat) / wall}
            res[f"{t['name']}@c{conc}"] = r
            print(f"{t['name']} c={conc}: p50 {r['p50']:.2f} ms, p90 {r['p90']:.2f}, p99 {r['p99']:.2f}, max {r['max']:.2f}, {r['req_s']:.0f} req/s", file=sys.stderr)
    if args.out:
        json.dump(res, open(args.out, "w"), indent=1)


def cmd_pairs(args):
    t = parse_target(args.target[0])
    cl = Client(t)
    out = {}
    for name, pairs in (("paraphrase", PARAPHRASES), ("near_miss", NEAR_MISSES)):
        texts = [x for p in pairs for x in p]
        vs = [norm(v) for v in cl.embed_many([args.prefix + x for x in texts])]
        sims = [cos(vs[2 * i], vs[2 * i + 1]) for i in range(len(pairs))]
        out[name] = [{"a": a, "b": b, "sim": s} for (a, b), s in zip(pairs, sims)]
        print(f"{name}: n={len(sims)} min {min(sims):.3f} p10 {pct(sims,.1):.3f} p50 {pct(sims,.5):.3f} p90 {pct(sims,.9):.3f} max {max(sims):.3f}", file=sys.stderr)
    para = [x["sim"] for x in out["paraphrase"]]
    near = [x["sim"] for x in out["near_miss"]]
    sweep = []
    for i in range(70, 100):
        th = i / 100
        sweep.append({"threshold": th, "paraphrase_hit_rate": sum(s >= th for s in para) / len(para), "near_miss_false_hit_rate": sum(s >= th for s in near) / len(near)})
    out["sweep"] = sweep
    for r in sweep:
        if r["threshold"] >= 0.8:
            print(f"  t={r['threshold']:.2f} hit {r['paraphrase_hit_rate']:.2f} false-hit {r['near_miss_false_hit_rate']:.2f}", file=sys.stderr)
    for x in sorted(out["near_miss"], key=lambda x: -x["sim"])[:8]:
        print(f"  near-miss {x['sim']:.3f}: {x['a']} | {x['b']}", file=sys.stderr)
    for x in sorted(out["paraphrase"], key=lambda x: x["sim"])[:6]:
        print(f"  paraphrase {x['sim']:.3f}: {x['a']} | {x['b']}", file=sys.stderr)
    if args.out:
        json.dump(out, open(args.out, "w"), indent=1)


def cmd_knn(args):
    """Leave-one-out kNN with the same maths as caliban-route's knn.rs, swept over T and thresholds."""
    t = parse_target(args.target[0])
    ds = json.load(open(args.dataset))
    texts, labels = [], []
    for intent, spec in sorted(ds["intents"].items()):
        for u in spec["utterances"]:
            texts.append(u)
            labels.append(intent)
    oos = list(ds.get("oos", []))
    cl = Client(t)
    t0 = time.perf_counter()
    V = [norm(v) for v in cl.embed_many([args.prefix + x for x in texts])]
    O = [norm(v) for v in cl.embed_many([args.prefix + x for x in oos])] if oos else []
    print(f"embedded {len(V)}+{len(O)} in {(time.perf_counter()-t0)*1000:.0f} ms, dim {len(V[0])}", file=sys.stderr)
    intents = sorted(set(labels))
    C = len(intents)
    sims = [[cos(V[i], V[j]) for j in range(len(V))] for i in range(len(V))]

    def classify(simrow, exclude, k, T, eps=1e-3):
        top = sorted(((s, j) for j, s in enumerate(simrow) if j != exclude), reverse=True)[:k]
        smax = top[0][0]
        w = [math.exp((s - smax) / T) for s, _ in top]
        tot = sum(w)
        votes = {}
        for (s, j), wj in zip(top, w):
            votes[labels[j]] = votes.get(labels[j], 0) + wj / tot
        ranked = sorted((((1 - eps) * v + eps / C), c) for c, v in votes.items())
        ranked.sort(key=lambda x: (-x[0], x[1]))
        pmax, intent = ranked[0]
        return intent, pmax, top[0][0]

    report = {"n": len(V), "intents": intents, "oos_n": len(O), "grid": []}
    for k in (args.k,):
        for T in (0.01, 0.02, 0.03, 0.05, 0.1, 0.2):
            res = [classify(sims[i], i, k, T) for i in range(len(V))]
            acc = sum(r[0] == labels[i] for i, r in enumerate(res)) / len(V)
            row = {"k": k, "T": T, "top1": acc, "abstain": {}}
            for thr in (0.4, 0.5, 0.6, 0.7, 0.8, 0.9):
                acc_rows = [(r[0] == labels[i]) for i, r in enumerate(res) if r[1] >= thr]
                row["abstain"][thr] = {"abstain_rate": 1 - len(acc_rows) / len(V), "accepted_precision": (sum(acc_rows) / len(acc_rows)) if acc_rows else None}
            report["grid"].append(row)
            print(f"k={k} T={T}: top-1 {acc:.3f} | " + ", ".join(f"thr {th}: abst {v['abstain_rate']:.2f} prec {v['accepted_precision'] or 0:.3f}" for th, v in row["abstain"].items()), file=sys.stderr)
    # Per-intent + confusions at the default T
    T = args.T
    res = [classify(sims[i], i, args.k, T) for i in range(len(V))]
    per, conf = {}, {}
    for i, r in enumerate(res):
        p = per.setdefault(labels[i], [0, 0])
        p[0] += 1
        p[1] += r[0] == labels[i]
        if r[0] != labels[i]:
            conf[f"{labels[i]} -> {r[0]}"] = conf.get(f"{labels[i]} -> {r[0]}", 0) + 1
            report.setdefault("errors", []).append({"text": texts[i], "truth": labels[i], "pred": r[0], "p": r[1], "top1": r[2]})
    report["per_intent"] = {k2: {"n": v[0], "top1": v[1] / v[0]} for k2, v in per.items()}
    report["confusions"] = dict(sorted(conf.items(), key=lambda x: -x[1]))
    in_top1 = [max(s for j, s in enumerate(sims[i]) if j != i) for i in range(len(V))]
    oos_top1 = [max(cos(o, v) for v in V) for o in O]
    report["in_scope_top1"] = {"p01": pct(in_top1, .01), "p05": pct(in_top1, .05), "p10": pct(in_top1, .1), "p50": pct(in_top1, .5)}
    if O:
        report["oos_top1"] = {"min": min(oos_top1), "p50": pct(oos_top1, .5), "p90": pct(oos_top1, .9), "max": max(oos_top1), "values": sorted(oos_top1)}
        sweep = []
        for i in range(40, 90):
            g = i / 100
            sweep.append({"oos_threshold": g, "oos_rejected": sum(x < g for x in oos_top1) / len(O), "in_scope_rejected": sum(x < g for x in in_top1) / len(V)})
        report["oos_sweep"] = sweep
        print(f"OOS top-1 sim: min {min(oos_top1):.3f} p50 {pct(oos_top1,.5):.3f} p90 {pct(oos_top1,.9):.3f} max {max(oos_top1):.3f}; in-scope top-1 p01 {pct(in_top1,.01):.3f} p05 {pct(in_top1,.05):.3f} p10 {pct(in_top1,.1):.3f} p50 {pct(in_top1,.5):.3f}", file=sys.stderr)
    print(json.dumps({"per_intent": report["per_intent"], "confusions": report["confusions"]}, indent=1), file=sys.stderr)
    if args.out:
        json.dump(report, open(args.out, "w"), indent=1)


ap = argparse.ArgumentParser()
ap.add_argument("cmd", choices=["latency", "pairs", "knn"])
ap.add_argument("--target", action="append", required=True)
ap.add_argument("--n", type=int, default=300)
ap.add_argument("--concurrency", default="1")
ap.add_argument("--prefix", default="")
ap.add_argument("--dataset")
ap.add_argument("--k", type=int, default=5)
ap.add_argument("--T", type=float, default=0.05)
ap.add_argument("--out")
ap.add_argument("--tag", default="", help="prefix for the per-request variant, so repeated runs miss the gateway embedding cache")
a = ap.parse_args()
{"latency": cmd_latency, "pairs": cmd_pairs, "knn": cmd_knn}[a.cmd](a)
