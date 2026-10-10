#!/usr/bin/env python3
"""caliban/auto against a pinned model against the model server directly (stdlib only, Python 3.9+).

Streams the same prompts to three targets and measures time to first token (TTFT, first content
delta), time to the response headers and the full round trip:

  direct   the model server (vLLM) itself
  pinned   Caliban with the model named explicitly (no intent classification)
  auto     Caliban with model "caliban/auto" (Stage-1 kNN on the embedder, then the route table)

c = 1 is paired: request i sends the same prompt to the three targets back to back, in an order
that rotates with i, so per-prompt differences (auto - pinned) cancel prompt length and prefix-cache
effects. c > 1 runs each target as its own closed-loop level, in rotating order, for several rounds
with the same prompt sequence per round.

  auto_bench.py run --direct http://$GPU_IP:8000,Qwen/Qwen3.8-27B-FP8 \
      --gateway http://$GATEWAY_IP:8080 --key KEY --pinned local/qwen3.8-27b \
      --concurrency 1,8,32 --pairs 40 --requests 64 --rounds 3 --max-tokens 64 --out res.json
  auto_bench.py bg --url http://$GPU_IP:8000,Qwen/Qwen3.8-27B-FP8 --streams 8 --max-tokens 512
"""
import argparse, asyncio, json, random, statistics, sys, time
from urllib.parse import urlparse

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.abspath(__file__)))
from llm_bench import PROMPTS, Conn, read_headers, body_chunks, pct  # noqa: E402


async def one(conn, path, body, headers):
    payload = json.dumps(body).encode()
    req = (f"POST {path} HTTP/1.1\r\nHost: {conn.host}:{conn.port}\r\n"
           f"Content-Type: application/json\r\nAccept: text/event-stream\r\nContent-Length: {len(payload)}\r\n")
    for k, v in headers.items():
        req += f"{k}: {v}\r\n"
    req = req.encode() + b"\r\n" + payload
    for attempt in range(2):
        try:
            await conn.ensure()
            t0 = time.perf_counter()
            conn.w.write(req)
            await conn.w.drain()
            code, h = await read_headers(conn.r)
            t_head = time.perf_counter()
            break
        except (ConnectionError, asyncio.IncompleteReadError, OSError):
            conn.close()
            if attempt:
                raise
    t_first = None
    n_tok = 0
    usage = None
    buf = b""
    raw = b""
    async for chunk in body_chunks(conn.r, h):
        if code != 200:
            raw += chunk
            continue
        buf += chunk
        while b"\n\n" in buf:
            ev, buf = buf.split(b"\n\n", 1)
            for line in ev.split(b"\n"):
                if not line.startswith(b"data:"):
                    continue
                d = line[5:].strip()
                if d == b"[DONE]":
                    continue
                try:
                    j = json.loads(d)
                except ValueError:
                    continue
                if j.get("usage"):
                    usage = j["usage"]
                for ch in j.get("choices") or []:
                    delta = ch.get("delta") or {}
                    if delta.get("content") or delta.get("reasoning_content") or delta.get("reasoning"):
                        n_tok += 1
                        if t_first is None:
                            t_first = time.perf_counter()
    t_end = time.perf_counter()
    if h.get("connection", "").lower() == "close":
        conn.close()
    if code != 200:
        raise RuntimeError(f"HTTP {code}: {raw[:300]!r}")
    return {
        "head_ms": (t_head - t0) * 1000,
        "ttft_ms": (t_first - t0) * 1000 if t_first else None,
        "e2e_ms": (t_end - t0) * 1000,
        "out_tokens": (usage or {}).get("completion_tokens") or n_tok,
        "intent": h.get("x-caliban-intent"),
        "routed": h.get("x-caliban-routed-model"),
        "cache": h.get("x-caliban-cache"),
        "request_id": h.get("x-caliban-request-id"),
    }


UNIQUE = [False]
RUN = [""]


def text_for(p, tag):
    return PROMPTS[p] + (f" (ticket {RUN[0]}-{tag})" if UNIQUE[0] else "")


def body_for(model, prompt, max_tokens, ignore_eos=True):
    return {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "temperature": 0.7,
        "stream": True,
        "stream_options": {"include_usage": True},
        "ignore_eos": ignore_eos,
        "chat_template_kwargs": {"enable_thinking": False},
    }


def make_targets(a):
    d_url, d_model = a.direct.split(",", 1)
    du, gu = urlparse(d_url), urlparse(a.gateway)
    auth = {"Authorization": f"Bearer {a.key}"}
    return [
        {"name": "direct", "host": du.hostname, "port": du.port or 80, "model": d_model, "headers": {}},
        {"name": "pinned", "host": gu.hostname, "port": gu.port or 80, "model": a.pinned, "headers": auth},
        {"name": "auto", "host": gu.hostname, "port": gu.port or 80, "model": "caliban/auto", "headers": auth},
    ]


async def paired(targets, n, a, seed):
    rnd = random.Random(seed)
    conns = {t["name"]: Conn(t["host"], t["port"]) for t in targets}
    rows = []
    for i in range(n):
        p = rnd.randrange(len(PROMPTS))
        order = targets[i % 3:] + targets[:i % 3]
        row = {"i": i, "prompt": p, "text": text_for(p, f"{seed}-{i}")}
        for t in order:
            try:
                row[t["name"]] = await one(conns[t["name"]], "/v1/chat/completions", body_for(t["model"], row["text"], a.max_tokens), t["headers"])
            except Exception as e:  # noqa: BLE001
                row[t["name"]] = {"error": str(e)[:300]}
                conns[t["name"]].close()
        rows.append(row)
    for c in conns.values():
        c.close()
    return rows


async def level(t, conc, n, a, seed):
    rnd = random.Random(seed)
    order = [rnd.randrange(len(PROMPTS)) for _ in range(n)]
    q = asyncio.Queue()
    for k, p in enumerate(order):
        q.put_nowait((k, p))
    out, errors = [], []

    async def worker():
        conn = Conn(t["host"], t["port"])
        while True:
            try:
                k, p = q.get_nowait()
            except asyncio.QueueEmpty:
                break
            try:
                r = await one(conn, "/v1/chat/completions", body_for(t["model"], text_for(p, f"{seed}-{k}"), a.max_tokens), t["headers"])
                r["k"], r["prompt"] = k, p
                out.append(r)
            except Exception as e:  # noqa: BLE001
                errors.append(str(e)[:300])
                conn.close()
        conn.close()

    t0 = time.perf_counter()
    await asyncio.gather(*[worker() for _ in range(conc)])
    return {"target": t["name"], "rows": out, "errors": errors, "wall_s": time.perf_counter() - t0}


def summ(xs):
    xs = [x for x in xs if x is not None]
    if not xs:
        return {}
    return {"n": len(xs), "p50": pct(xs, .5), "p90": pct(xs, .9), "p99": pct(xs, .99), "mean": statistics.mean(xs)}


def boot_ci(diffs, stat=lambda v: pct(v, .5), it=2000, seed=1):
    if len(diffs) < 5:
        return None
    rnd = random.Random(seed)
    vals = sorted(stat([rnd.choice(diffs) for _ in diffs]) for _ in range(it))
    return [vals[int(.025 * it)], vals[int(.975 * it)]]


async def cmd_run(a):
    UNIQUE[0] = False
    targets = make_targets(a)
    # Warm-up: every prompt once per target (fills each side's prefix cache alike).
    for t in targets:
        r = await level(t, 6, len(PROMPTS) * 2, a, seed=0)
        print(f"warm-up {t['name']}: {len(r['rows'])} ok, {len(r['errors'])} errors {r['errors'][:1]}", file=sys.stderr)
    UNIQUE[0] = a.unique
    RUN[0] = a.label
    res = {"label": a.label, "max_tokens": a.max_tokens, "unique": a.unique, "levels": []}
    for c in [int(x) for x in a.concurrency.split(",")]:
        if c == 1:
            rows = await paired(targets, a.pairs, a, seed=101 + (7 if a.unique else 0))
            lv = {"concurrency": 1, "mode": "paired", "rows": rows}
            ok = [r for r in rows if all("ttft_ms" in r.get(t["name"], {}) for t in targets)]
            for f in ("ttft_ms", "e2e_ms", "head_ms"):
                lv[f] = {t["name"]: summ([r[t["name"]][f] for r in ok]) for t in targets}
            for x, y in (("auto", "pinned"), ("pinned", "direct"), ("auto", "direct")):
                for f in ("ttft_ms", "e2e_ms"):
                    d = [r[x][f] - r[y][f] for r in ok if r[x][f] is not None and r[y][f] is not None]
                    lv[f"diff_{x}_{y}_{f}"] = {**summ(d), "ci95_p50": boot_ci(d)}
            lv["errors"] = sum(1 for r in rows for t in targets if "error" in r.get(t["name"], {}))
            res["levels"].append(lv)
            s = lv["diff_auto_pinned_ttft_ms"]
            print(f"c=1 paired n={len(ok)}: TTFT p50 direct {lv['ttft_ms']['direct'].get('p50', 0):.1f} pinned {lv['ttft_ms']['pinned'].get('p50', 0):.1f} "
                  f"auto {lv['ttft_ms']['auto'].get('p50', 0):.1f}; auto-pinned p50 {s.get('p50', 0):.2f} ms CI {s.get('ci95_p50')}, errors {lv['errors']}", file=sys.stderr)
        else:
            n = max(a.requests, 2 * c)
            merged = {t["name"]: [] for t in targets}
            for rnd in range(a.rounds):
                order = targets[rnd % 3:] + targets[:rnd % 3]
                for t in order:
                    r = await level(t, c, n, a, seed=1000 * c + rnd)
                    for x in r["rows"]:
                        x["round"] = rnd
                    merged[t["name"]].append(r)
                    tt = summ([x["ttft_ms"] for x in r["rows"]])
                    print(f"c={c} round {rnd} {t['name']}: ttft p50 {tt.get('p50', 0):.1f} ms, n {len(r['rows'])}, errors {len(r['errors'])} {r['errors'][:1]}", file=sys.stderr)
            lv = {"concurrency": c, "mode": "levels", "rounds": merged}
            for f in ("ttft_ms", "e2e_ms", "head_ms"):
                lv[f] = {k: summ([x[f] for r in v for x in r["rows"]]) for k, v in merged.items()}
            # Per-round p50 differences (each round: same prompt sequence for every target).
            for x, y in (("auto", "pinned"), ("pinned", "direct")):
                lv[f"round_p50_diff_{x}_{y}_ttft_ms"] = [
                    pct([q["ttft_ms"] for q in merged[x][i]["rows"]], .5) - pct([q["ttft_ms"] for q in merged[y][i]["rows"]], .5)
                    for i in range(a.rounds)]
            lv["out_tok_s"] = {k: sum(x["out_tokens"] for r in v for x in r["rows"]) / sum(r["wall_s"] for r in v) for k, v in merged.items()}
            lv["errors"] = {k: sum(len(r["errors"]) for r in v) for k, v in merged.items()}
            res["levels"].append(lv)
            print(f"c={c}: TTFT p50 " + ", ".join(f"{k} {v.get('p50', 0):.1f}" for k, v in lv["ttft_ms"].items())
                  + f"; per-round auto-pinned {[round(d, 1) for d in lv['round_p50_diff_auto_pinned_ttft_ms']]}", file=sys.stderr)
    intents = {}
    for lv in res["levels"]:
        src = [r.get("auto", {}) for r in lv.get("rows", [])] + [x for v in lv.get("rounds", {}).get("auto", []) for x in v["rows"]]
        for x in src:
            k = (x.get("intent") or "?").split(";stage=")[-1] + " -> " + str(x.get("routed"))
            intents[k] = intents.get(k, 0) + 1
    res["auto_stages"] = intents
    print(f"auto stages: {intents}", file=sys.stderr)
    with open(a.out, "w") as f:
        json.dump(res, f, indent=1)


async def cmd_bg(a):
    url, model = a.url.split(",", 1)
    u = urlparse(url)
    rnd = random.Random(5)
    stop = time.time() + a.seconds
    done = [0]

    async def worker():
        conn = Conn(u.hostname, u.port or 80)
        while time.time() < stop:
            try:
                await one(conn, "/v1/chat/completions", body_for(model, PROMPTS[rnd.randrange(len(PROMPTS))] + f" (variant {rnd.random()})", a.max_tokens), {})
                done[0] += 1
            except Exception:  # noqa: BLE001
                conn.close()
                await asyncio.sleep(1)

    await asyncio.gather(*[worker() for _ in range(a.streams)])
    print(f"background: {done[0]} requests", file=sys.stderr)


ap = argparse.ArgumentParser()
ap.add_argument("cmd", choices=["run", "bg"])
ap.add_argument("--direct")
ap.add_argument("--gateway")
ap.add_argument("--key")
ap.add_argument("--pinned", default="local/qwen3.8-27b")
ap.add_argument("--concurrency", default="1,8,32")
ap.add_argument("--pairs", type=int, default=40)
ap.add_argument("--requests", type=int, default=64)
ap.add_argument("--rounds", type=int, default=3)
ap.add_argument("--max-tokens", type=int, default=64)
ap.add_argument("--label", default="")
ap.add_argument("--unique", action="store_true", help="append a unique ticket number to every prompt (no embedding-cache hits)")
ap.add_argument("--out")
ap.add_argument("--url")
ap.add_argument("--streams", type=int, default=8)
ap.add_argument("--seconds", type=int, default=3600)
a = ap.parse_args()
asyncio.run(cmd_run(a) if a.cmd == "run" else cmd_bg(a))
