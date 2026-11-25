"""E10: attack-case matrix. Each scenario is run as three variants and scored at a fixed 5 % benign FPR operating point."""
from common import *

VARIANTS = {"baseline": dict(sev=1.0, blend=1.0), "low_and_slow": dict(sev=0.5, blend=1.0), "adaptive_blend": dict(sev=1.0, blend=0.6)}

def threshold_at_fpr(scores_benign, fpr=0.05): return float(np.quantile(scores_benign, 1 - fpr))

def run(seeds=SEEDS):
    rows = []
    for s in seeds:
        D = build(s); tr, va = D["tr"], D["va"]
        models = {"standard": fit_logreg(D["Z"][tr], D["y"][tr], seed=s, epochs=2000), "pgd_trained": fit_logreg(D["Z"][tr], D["y"][tr], seed=s, epochs=2000, adv_eps=0.3, adv_steps=5)}
        r = np.random.default_rng(s + 99)
        for mn, m in models.items():
            for pi, proto in enumerate(T.PROTOCOLS):
                bv = va[(D["y"][va] == 0) & (D["p"][va] == pi)]; thr = threshold_at_fpr(m.predict_proba(D["Z"][bv]))
                for sid, sc in T.SCENARIOS.items():
                    if sc.protocol not in ("ALL", proto): continue
                    for vn, v in VARIANTS.items():
                        Xb = T.benign(proto, 600, r); Xa = T.attack(sid, proto, 600, r, v["sev"]); Xa = Xb + v["blend"] * (Xa - Xb)
                        p = m.predict_proba((Xa - D["mu"]) / D["sd"]); rows.append(dict(seed=s, model=mn, protocol=proto, scenario=sid, variant=vn, recall_at_5pct_fpr=float((p > thr).mean())))
    df = pd.DataFrame(rows)
    g = df.groupby(["model", "protocol", "scenario", "variant"]).agg(recall=("recall_at_5pct_fpr", "mean"), sd=("recall_at_5pct_fpr", "std")).reset_index()
    save_table(g, "e10_attack_case_matrix", "E10. Attack-case matrix: recall at a 5% benign FPR operating point, 5 seeds")
    w = g[g.model == "standard"].pivot_table(index=["scenario", "protocol"], columns="variant", values="recall").reset_index()
    save_table(w, "e10_case_matrix_wide", "E10b. Standard detector, recall by variant")
    fig, ax = plt.subplots(figsize=(7.5, 4.2)); lab = [f"{a} ({b})" for a, b in zip(w.scenario, w.protocol)]; x = np.arange(len(w))
    for i, (vn, c) in enumerate(zip(VARIANTS, ("#1a9850", "#e67e22", "#c0392b"))): ax.bar(x + (i - 1) * 0.27, w[vn], 0.27, label=vn, color=c)
    ax.set_xticks(x); ax.set_xticklabels(lab, rotation=65, ha="right", fontsize=6); ax.set_ylabel("recall @ 5% FPR"); ax.legend(fontsize=7); savefig(fig, "e10_attack_case_matrix"); return g, w

if __name__ == "__main__": g, w = run(); print(w.round(3).to_string())
