"""E8: threat-intelligence fusion and darknet scan detection (Section 6.7)."""
from common import *
import json, time
from a3e_dns_v2.intel import *

def make_feeds(r, n_bad=2000, n_good=8000):
    bad = [f"bad{i}.example" for i in range(n_bad)]; good = [f"ok{i}.example" for i in range(n_good)]
    def feed(name, tpr, fpr):
        rows = []
        for d in bad:
            if r.random() < tpr: rows.append(dict(value=d, score=int(np.clip(r.normal(75, 15), 5, 99))))
        for d in good:
            if r.random() < fpr: rows.append(dict(value=d, score=int(np.clip(r.normal(45, 15), 5, 99))))
        return normalize_vendor_feed(rows, name)
    stix_objs = [dict(type="indicator", pattern=f"[domain-name:value = '{d}']", confidence=int(np.clip(r.normal(70, 15), 5, 99)), valid_from="2026-01-01T00:00:00Z", created_by_ref="stix-feed") for d in bad if r.random() < 0.45]
    stix_objs += [dict(type="indicator", pattern=f"[domain-name:value = '{d}']", confidence=40, created_by_ref="stix-feed") for d in good if r.random() < 0.01]
    return bad, good, feed("vendorA", 0.55, 0.03), feed("vendorB", 0.4, 0.015), json.dumps(dict(type="bundle", objects=stix_objs))

def run(seed=3):
    r = np.random.default_rng(seed); bad, good, A, B, bundle = make_feeds(r); badset = set(bad)
    t0 = time.perf_counter(); S = parse_stix_bundle(bundle); t_parse = time.perf_counter() - t0
    for i in S: i["w"] = 1.0
    rep = dict(vendorA=0.9, vendorB=0.9, **{"stix-feed": 0.9})
    t0 = time.perf_counter(); fused = fuse_indicators(A, B, S, reputation=rep); t_fuse = time.perf_counter() - t0
    def eval_(scores, thr):
        flagged = {k[1] for k, v in scores.items() if v >= thr}; tp = len(flagged & badset); fp = len(flagged - badset)
        return tp / max(len(badset), 1), tp / max(len(flagged), 1), fp
    rows = []
    singles = {"vendorA": {(i["kind"], i["value"]): i["confidence"] for i in A}, "vendorB": {(i["kind"], i["value"]): i["confidence"] for i in B}, "stix": {(i["kind"], i["value"]): i["confidence"] for i in S}}
    singles["fused (noisy-OR)"] = {k: v["score"] for k, v in fused.items()}
    for name, sc in singles.items():
        for thr in (0.3, 0.5, 0.7):
            rc, pr, fp = eval_(sc, thr); rows.append(dict(source=name, threshold=thr, recall=rc, precision=pr, false_positives=fp))
    df = pd.DataFrame(rows); save_table(df, "e8_intel_fusion", "E8a. Indicator fusion: recall/precision per source and for the fused score (synthetic feeds with known ground truth)")
    lat = []
    for n in (1_000, 10_000, 100_000):
        b = json.dumps(dict(type="bundle", objects=[dict(type="indicator", pattern=f"[domain-name:value = 'x{i}.example']", confidence=60) for i in range(n)]))
        t0 = time.perf_counter(); ind = parse_stix_bundle(b); fuse_indicators(ind); dt = time.perf_counter() - t0; lat.append(dict(indicators=n, seconds=dt, indicators_per_s=n / dt))
    d2 = pd.DataFrame(lat); save_table(d2, "e8_intel_throughput", "E8b. STIX parse + fuse throughput (single thread, host in run_metadata.json); Chapter 6 requires batches under 100 ms"); 
    rec = []
    for i in range(30): rec += [(float(t), f"10.0.0.{i}", int(r.choice([80, 443, 853, 8443]))) for t in r.uniform(0, 600, 12)]
    for i in range(5): rec += [(float(t), f"203.0.113.{i}", int(p)) for t, p in zip(np.sort(r.uniform(100, 140, 40)), r.integers(1, 3000, 40))]
    sc = []
    for mp in (4, 8, 16, 32):
        f = detect_darknet_scans(rec, min_ports=mp); tp = sum(k.startswith("203.") for k in f); fp = len(f) - tp; sc.append(dict(min_ports=mp, scanners_found=tp, of=5, false_flags=fp))
    d3 = pd.DataFrame(sc); save_table(d3, "e8_darknet_scans", "E8c. Darknet scan detection: 5 injected scanners among 30 benign sources")
    fig, ax = plt.subplots(1, 2, figsize=(8, 3))
    for name in singles:
        s = df[df.source == name]; ax[0].plot(s.recall, s.precision, "o-", label=name)
    ax[0].set_xlabel("recall"); ax[0].set_ylabel("precision"); ax[0].legend(fontsize=6); ax[0].set_title("Fusion (thresholds 0.3 / 0.5 / 0.7)")
    ax[1].loglog(d2.indicators, d2.indicators_per_s, "o-"); ax[1].set_xlabel("batch size"); ax[1].set_ylabel("indicators / s"); savefig(fig, "e8_intel"); return df, d2, d3

if __name__ == "__main__": a, b, c = run(); print(a.round(3).to_string()); print(b.round(3)); print(c)
