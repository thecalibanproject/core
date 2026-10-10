import gzip, json, re, sys
R = sys.argv[1]; tag = sys.argv[2]
def pct(xs, p):
    xs = sorted(xs)
    if not xs: return float('nan')
    k = (len(xs)-1)*p; f = int(k); c = min(f+1, len(xs)-1); return xs[f]+(xs[c]-xs[f])*(k-f)
d = json.load(open(f'{R}/s1-{tag}.json'))
lines = gzip.open(f'{R}/{tag}.route.log.gz', 'rt').read().splitlines()
recs = []
for l in lines:
    us = re.search(r'knn_us=Some\((\d+)\)', l); st = re.search(r'stage="?(\w+)', l); fb = re.search(r'knn_fallback=Some\("?(\w+)', l)
    recs.append((int(us.group(1))/1000 if us else None, st.group(1), fb.group(1) if fb else None))
# order: warm-up 36, c=1 pairs, then levels
i = 36
print(f'== {tag}: route log lines {len(recs)}')
for lv in d['levels']:
    c = lv['concurrency']
    n = len(lv['rows']) if c == 1 else sum(len(r['rows']) for r in lv['rounds']['auto'])
    seg = recs[i:i+n]; i += n
    ms = [x[0] for x in seg if x[0] is not None]
    to = sum(1 for x in seg if x[2] == 'timeout'); ab = sum(1 for x in seg if x[2] and x[2].startswith('abstain')); kn = sum(1 for x in seg if x[1] == 'knn')
    line = f"c={c}: n={n} stage1 ms p50 {pct(ms,.5):.2f} p90 {pct(ms,.9):.2f} p99 {pct(ms,.99):.2f}; knn {kn}, abstain {ab}, timeout {to} ({100*to/n:.0f}%)"
    t = lv['ttft_ms']; e = lv['e2e_ms']
    line += f" | TTFT p50 direct {t['direct']['p50']:.1f} pinned {t['pinned']['p50']:.1f} auto {t['auto']['p50']:.1f}; p90 {t['direct']['p90']:.1f}/{t['pinned']['p90']:.1f}/{t['auto']['p90']:.1f}; e2e p50 {e['direct']['p50']:.0f}/{e['pinned']['p50']:.0f}/{e['auto']['p50']:.0f}"
    print(line)
    if c == 1:
        for k in ('diff_auto_pinned_ttft_ms', 'diff_auto_pinned_e2e_ms', 'diff_pinned_direct_ttft_ms', 'diff_auto_direct_ttft_ms'):
            v = lv[k]; print(f"   {k}: p50 {v['p50']:.2f} CI {[round(x,2) for x in v['ci95_p50']]} mean {v['mean']:.2f} p90 {v['p90']:.2f}")
    else:
        print('   per-round p50 auto-pinned', [round(x,1) for x in lv['round_p50_diff_auto_pinned_ttft_ms']], 'pinned-direct', [round(x,1) for x in lv['round_p50_diff_pinned_direct_ttft_ms']], 'tok/s', {k: round(v) for k, v in lv['out_tok_s'].items()}, 'errors', lv['errors'])
print('stages', d['auto_stages'])
