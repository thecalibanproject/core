#!/usr/bin/env python3
"""Stage-1 timing from the gateway's debug route log (CALIBAN_LOG=...,caliban_route=debug).

  docker logs --since 2026-10-10T11:00:00Z caliban-caliban-1 2>&1 | knn_log.py [--tenant ID] > out.json

Reads "route decision" lines (text or JSON format) and summarises knn_us (embed + kNN classify wall
time, microseconds) by stage and fallback reason.
"""
import json, re, sys

def pct(xs, p):
    xs = sorted(xs)
    if not xs:
        return None
    k = (len(xs) - 1) * p
    f = int(k)
    c = min(f + 1, len(xs) - 1)
    return xs[f] + (xs[c] - xs[f]) * (k - f)

ten = sys.argv[sys.argv.index("--tenant") + 1] if "--tenant" in sys.argv else None
rx = {k: re.compile(k + r'[=":\s]+(?:Some\()?"?([A-Za-z0-9_.\-]+)') for k in ("knn_us", "stage", "knn_fallback", "tenant", "intent", "chosen")}
rows = []
for line in sys.stdin:
    line = re.sub(r"\[[0-9;]*m", "", line)
    if "route decision" not in line:
        continue
    r = {}
    for k, x in rx.items():
        m = x.search(line)
        if m:
            r[k] = m.group(1)
    if ten and r.get("tenant") != ten:
        continue
    rows.append(r)
out = {"n": len(rows), "by_stage": {}}
for st in sorted({(r.get("stage"), r.get("knn_fallback")) for r in rows}, key=str):
    us = [int(r["knn_us"]) for r in rows if (r.get("stage"), r.get("knn_fallback")) == st and r.get("knn_us", "").isdigit()]
    out["by_stage"][f"{st[0]}/{st[1]}"] = {"n": sum(1 for r in rows if (r.get("stage"), r.get("knn_fallback")) == st),
                                          "knn_ms": {q: (pct(us, v) / 1000 if us else None) for q, v in (("p50", .5), ("p90", .9), ("p99", .99), ("max", 1.0))},
                                          "n_timed": len(us)}
intents = {}
for r in rows:
    intents[r.get("intent")] = intents.get(r.get("intent"), 0) + 1
out["intents"] = intents
json.dump(out, sys.stdout, indent=1)
print()
