#!/usr/bin/env python3
"""Closed-loop streaming chat benchmark (stdlib only, Python 3.9+).

Measures TTFT (first content or reasoning token), inter-token time, end-to-end latency and
output tokens/s against an OpenAI-compatible /v1/chat/completions endpoint, direct (vLLM) or
through Caliban. Keep-alive HTTP/1.1, one connection per worker.

  llm_bench.py --target direct=http://$GPU_IP:8000,Qwen/Qwen3.8-27B-FP8 \
               --target caliban=http://$GATEWAY_IP:8080,local/qwen3.8-27b,KEY \
               --concurrency 1,8,32 --requests 32 --max-tokens 256 --out res.json
"""
import argparse, asyncio, json, random, statistics, sys, time
from urllib.parse import urlparse

PROMPTS = [
    "Explain the difference between a mutex and a semaphore, with a short example in Rust.",
    "Write a polite email to a supplier asking to move next Tuesday's delivery to Thursday because our warehouse is being inspected.",
    "Summarise the main trade-offs between PostgreSQL and MongoDB for an analytics workload with frequent schema changes.",
    "Our sales were 1.2M in Q1, 1.5M in Q2, 1.1M in Q3 and 1.9M in Q4. Describe the trend and suggest three possible explanations.",
    "Translate into French and German: 'The meeting has been postponed until further notice. Please keep the documents confidential.'",
    "Review this Python function and suggest improvements:\n\ndef avg(xs):\n    s = 0\n    for i in range(len(xs)):\n        s = s + xs[i]\n    return s / len(xs)\n",
    "Extract the company names, dates and amounts from this text as JSON: 'On 3 March 2026 Acme Corp paid Globex Ltd 45,000 EUR for consulting; on 12 April Initech invoiced Acme 12,500 EUR.'",
    "What are the main causes of inflation, and how do central banks typically respond? Keep it under 300 words.",
    "Draft a short product description for a waterproof hiking backpack with a 30 litre capacity and a laptop sleeve.",
    "Write a SQL query that returns the top five customers by total order value in 2025 from tables customers(id, name) and orders(id, customer_id, amount, created_at).",
    "Give me a step-by-step plan to migrate a monolithic web application to microservices with minimal downtime.",
    "Explain how TLS 1.3 handshakes work to a junior engineer, including what forward secrecy means.",
    "Compare three approaches to rate limiting (fixed window, sliding window, token bucket) and say when you would use each.",
    "A customer says their invoice total is wrong: 3 items at 19.99, 2 at 4.50 and a 10% discount on the total. Compute the correct total and explain.",
    "Write a haiku sequence (three haiku) about autumn in a port city.",
    "List the key clauses to check in a software licence agreement before signing it, and why each matters.",
] + [
    # Longer, document-style prompts (a few hundred tokens of context).
    ("Read the following incident report and write a five-bullet executive summary with the root cause and the follow-up actions.\n\n"
     + " ".join([
        "At 02:14 UTC the payment service started returning HTTP 502 for about 18% of requests.",
        "The on-call engineer was paged at 02:16 and found that one of three database replicas had fallen behind by more than 40 seconds.",
        "The connection pool kept routing reads to the lagging replica because the health check only verified TCP connectivity.",
        "At 02:41 the replica was removed from the pool manually and error rates returned to normal within two minutes.",
        "The lag was caused by a long-running analytical query started by a scheduled report job that had been moved to the production cluster the previous week.",
        "No data was lost, but 3,200 payments had to be retried by customers, and support received 140 tickets.",
     ] * 4)),
    ("Here is a meeting transcript. List the decisions, the owners and the deadlines as a table.\n\n"
     + " ".join([
        "Anna: We need the new onboarding flow live before the end of the quarter.",
        "Ben: Design can deliver final screens by the 14th if we freeze scope today.",
        "Anna: Agreed, scope is frozen. Carla, can engineering start on the 15th?",
        "Carla: Yes, two engineers from the 15th, and we can ship behind a flag by the 30th.",
        "David: Legal must review the new consent text; I will send it to them tomorrow and expect feedback within a week.",
        "Anna: Then the go/no-go meeting is on the 1st, and I will own the launch communication.",
     ] * 4)),
]


def pct(xs, p):
    if not xs:
        return float("nan")
    xs = sorted(xs)
    k = (len(xs) - 1) * p
    f = int(k)
    c = min(f + 1, len(xs) - 1)
    return xs[f] + (xs[c] - xs[f]) * (k - f)


class Conn:
    def __init__(self, host, port):
        self.host, self.port = host, port
        self.r = self.w = None

    async def ensure(self):
        if self.w is None or self.w.is_closing():
            self.r, self.w = await asyncio.open_connection(self.host, self.port)

    def close(self):
        if self.w is not None:
            self.w.close()
        self.r = self.w = None


async def read_headers(r):
    status = await r.readline()
    if not status:
        raise ConnectionError("closed")
    code = int(status.split()[1])
    h = {}
    while True:
        line = await r.readline()
        if line in (b"\r\n", b"\n", b""):
            break
        k, _, v = line.decode("latin-1").partition(":")
        h[k.strip().lower()] = v.strip()
    return code, h


async def body_chunks(r, h):
    if h.get("transfer-encoding", "").lower() == "chunked":
        while True:
            size = int((await r.readline()).split(b";")[0].strip(), 16)
            if size == 0:
                await r.readline()
                return
            data = await r.readexactly(size)
            await r.readexactly(2)
            yield data
    elif "content-length" in h:
        n = int(h["content-length"])
        if n:
            yield await r.readexactly(n)
    else:
        while True:
            d = await r.read(65536)
            if not d:
                return
            yield d


async def one(conn, target, body, extra_headers):
    payload = json.dumps(body).encode()
    req = (f"POST {target['path']} HTTP/1.1\r\nHost: {conn.host}:{conn.port}\r\n"
           f"Content-Type: application/json\r\nAccept: text/event-stream\r\nContent-Length: {len(payload)}\r\n")
    for k, v in extra_headers.items():
        req += f"{k}: {v}\r\n"
    req = req.encode() + b"\r\n" + payload
    for attempt in range(2):
        try:
            await conn.ensure()
            t0 = time.perf_counter()
            conn.w.write(req)
            await conn.w.drain()
            code, h = await read_headers(conn.r)
            break
        except (ConnectionError, asyncio.IncompleteReadError, OSError):
            conn.close()
            if attempt:
                raise
    t_first = None
    tokens_seen = 0
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
                        tokens_seen += 1
                        if t_first is None:
                            t_first = time.perf_counter()
    t_end = time.perf_counter()
    if h.get("connection", "").lower() == "close":
        conn.close()
    if code != 200:
        raise RuntimeError(f"HTTP {code}: {raw[:300]!r}")
    out_tokens = (usage or {}).get("completion_tokens") or tokens_seen
    return {
        "ttft": (t_first - t0) if t_first else float("nan"),
        "e2e": t_end - t0,
        "out_tokens": out_tokens,
        "in_tokens": (usage or {}).get("prompt_tokens"),
        "itl": ((t_end - t_first) / max(out_tokens - 1, 1)) if t_first else float("nan"),
        "cache": h.get("x-caliban-cache"),
    }


async def run_level(target, conc, n, args, seed):
    rnd = random.Random(seed)
    order = [rnd.randrange(len(PROMPTS)) for _ in range(n)]
    q = asyncio.Queue()
    for i in order:
        q.put_nowait(i)
    results, errors = [], []
    headers = {}
    if target.get("key"):
        headers["Authorization"] = f"Bearer {target['key']}"

    async def worker():
        conn = Conn(target["host"], target["port"])
        while True:
            try:
                i = q.get_nowait()
            except asyncio.QueueEmpty:
                break
            body = {
                "model": target["model"],
                "messages": [{"role": "user", "content": PROMPTS[i]}],
                "max_tokens": args.max_tokens,
                "temperature": 0.7,
                "stream": True,
                "stream_options": {"include_usage": True},
                "ignore_eos": True,
                "chat_template_kwargs": {"enable_thinking": False},
            }
            try:
                results.append(await one(conn, target, body, headers))
            except Exception as e:  # noqa: BLE001
                errors.append(str(e)[:300])
                conn.close()
        conn.close()

    t0 = time.perf_counter()
    await asyncio.gather(*[worker() for _ in range(conc)])
    wall = time.perf_counter() - t0
    ttft = [r["ttft"] * 1000 for r in results if r["ttft"] == r["ttft"]]
    itl = [r["itl"] * 1000 for r in results if r["itl"] == r["itl"]]
    e2e = [r["e2e"] * 1000 for r in results]
    toks = sum(r["out_tokens"] for r in results)
    return {
        "target": target["name"], "concurrency": conc, "n": len(results), "errors": len(errors),
        "first_error": errors[0] if errors else None,
        "ttft_p50": pct(ttft, .5), "ttft_p90": pct(ttft, .9), "ttft_p99": pct(ttft, .99), "ttft_mean": statistics.mean(ttft) if ttft else None,
        "itl_p50": pct(itl, .5), "itl_p90": pct(itl, .9),
        "e2e_p50": pct(e2e, .5), "e2e_p90": pct(e2e, .9),
        "out_tok_s": toks / wall, "req_s": len(results) / wall, "wall_s": wall,
        "mean_out_tokens": toks / max(len(results), 1),
        "cache": sorted({r["cache"] for r in results if r["cache"]}),
        "raw_ttft": ttft, "raw_itl_p50": itl,
    }


def parse_target(s):
    name, _, rest = s.partition("=")
    parts = rest.split(",")
    u = urlparse(parts[0])
    return {"name": name, "host": u.hostname, "port": u.port or 80, "path": (u.path.rstrip("/") or "") + "/v1/chat/completions",
            "model": parts[1], "key": parts[2] if len(parts) > 2 else None}


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", action="append", required=True)
    ap.add_argument("--concurrency", default="1,8,32")
    ap.add_argument("--requests", type=int, default=32, help="per level per round per target (at least 2x concurrency is used)")
    ap.add_argument("--rounds", type=int, default=2)
    ap.add_argument("--warmup", type=int, default=len(PROMPTS))
    ap.add_argument("--max-tokens", type=int, default=256)
    ap.add_argument("--out")
    args = ap.parse_args()
    targets = [parse_target(t) for t in args.target]
    # Warm-up: every prompt once per target (fills each side's prefix cache alike).
    for t in targets:
        r = await run_level(t, 8, args.warmup, args, seed=0)
        print(f"warm-up {t['name']}: {r['n']} ok, {r['errors']} errors {r['first_error'] or ''}", file=sys.stderr)
    rows = []
    for c in [int(x) for x in args.concurrency.split(",")]:
        n = max(args.requests, 2 * c)
        merged = {t["name"]: [] for t in targets}
        for rnd in range(args.rounds):
            for t in targets:
                r = await run_level(t, c, n, args, seed=1000 * c + rnd)
                merged[t["name"]].append(r)
                print(f"c={c} round {rnd} {t['name']}: ttft p50 {r['ttft_p50']:.1f} ms, itl p50 {r['itl_p50']:.2f} ms, "
                      f"{r['out_tok_s']:.0f} tok/s, e2e p50 {r['e2e_p50']:.0f} ms, errors {r['errors']} {r['first_error'] or ''}", file=sys.stderr)
        rows.append({"concurrency": c, "rounds": merged})
    if args.out:
        with open(args.out, "w") as f:
            json.dump(rows, f, indent=1)


if __name__ == "__main__":
    asyncio.run(main())
