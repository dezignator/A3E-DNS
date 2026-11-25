"""E1: per-scenario / per-protocol detection and severity sweep. E9: adversarial evasion and PGD training."""
from common import *
from a3e_dns_v2.metrics import roc_auc

def run():
    rows, sweep, adv_rows = [], [], []
    for seed in SEEDS:
        D = build(seed); m = fit_logreg(D["Z"][D["tr"]], D["y"][D["tr"]], seed=seed)
        te = D["te"]; yp = (m.predict_proba(D["Z"][te]) > 0.5).astype(int)
        for si, sid in enumerate(T.SCENARIOS):
            for pi, pr in enumerate(T.PROTOCOLS):
                sel = te[(D["s"][te] == si) & (D["p"][te] == pi)]
                if len(sel) < 5: continue
                ben = te[(D["y"][te] == 0) & (D["p"][te] == pi)]
                idx = np.concatenate([sel, ben]); q = (m.predict_proba(D["Z"][idx]) > 0.5).astype(int); r = prf(D["y"][idx], q)
                rows.append(dict(seed=seed, scenario=sid, protocol=pr, auc=roc_auc(D["y"][idx], m.predict_proba(D["Z"][idx])), **r))
        for sev in (0.25, 0.5, 0.75, 1.0, 1.5):
            Ds = build(seed + 1000, severity=sev); ms = m
            Zs = (Ds["X"] - D["mu"]) / D["sd"]; q = (ms.predict_proba(Zs) > 0.5).astype(int); r = prf(Ds["y"], q)
            sweep.append(dict(seed=seed, severity=sev, **r))
        # E9: evasion strength alpha: attacker blends S2-Tunnel toward benign (alpha=1 pure tunnel, 0 pure benign)
        rr = np.random.default_rng(seed + 7)
        mAT = fit_logreg(D["Z"][D["tr"]], D["y"][D["tr"]], seed=seed, adv_eps=0.3, adv_steps=5)
        for name, mm in (("standard", m), ("pgd_trained", mAT)):
            Zt = D["Z"][te]; yt = D["y"][te]
            for eps in (0.0, 0.1, 0.2, 0.3, 0.5):
                Za = pgd(mm, Zt, yt, eps, 10) if eps > 0 else Zt
                q = (mm.predict_proba(Za) > 0.5).astype(int); r = prf(yt, q)
                adv_rows.append(dict(seed=seed, model=name, pgd_eps=eps, acc=r["acc"], f1=r["f1"], fpr=r["fpr"]))
        for alpha in (1.0, 0.8, 0.6, 0.4, 0.2):
            Xt = T.attack("S2-Tunnel", "DoH", 400, rr, 1.0); Xb = T.benign("DoH", 400, rr); Xe = Xb + alpha * (Xt - Xb)
            for name, mm in (("standard", m), ("pgd_trained", mAT)):
                rec = float((mm.predict_proba((Xe - D["mu"]) / D["sd"]) > 0.5).mean())
                adv_rows.append(dict(seed=seed, model=name, pgd_eps=-alpha, acc=rec, f1=np.nan, fpr=np.nan))
    df = pd.DataFrame(rows)
    g = df.groupby(["scenario", "protocol"]).agg(auc=("auc", "mean"), recall=("recall", "mean"), precision=("precision", "mean"),
                                                 f1=("f1", "mean"), fpr=("fpr", "mean"), f1_sd=("f1", "std")).reset_index()
    save_table(g, "e1_per_scenario_protocol", "E1. Detection by scenario and protocol (mean over 5 seeds; one-hidden-layer MLP detector)")
    sw = pd.DataFrame(sweep).groupby("severity").agg(f1=("f1", "mean"), recall=("recall", "mean"), fpr=("fpr", "mean"), acc=("acc", "mean")).reset_index()
    save_table(sw, "e1_severity_sweep", "E1b. Severity sweep (attack shift scaled; detector trained at severity 1.0)")
    A = pd.DataFrame(adv_rows)
    pg = A[A.pgd_eps >= 0].groupby(["model", "pgd_eps"]).agg(acc=("acc", "mean"), f1=("f1", "mean"), fpr=("fpr", "mean")).reset_index()
    ev = A[A.pgd_eps < 0].assign(blend=lambda d: -d.pgd_eps).groupby(["model", "blend"]).agg(detection_rate=("acc", "mean")).reset_index()
    save_table(pg, "e9_pgd_robustness", "E9a. L_inf PGD robustness in standardised feature units")
    save_table(ev, "e9_evasion_blend", "E9b. Detection rate of DoH tunnel traffic blended toward benign statistics")
    # figures
    fig, ax = plt.subplots(1, 3, figsize=(11, 3.2))
    pv = g.pivot(index="scenario", columns="protocol", values="f1").reindex(list(T.SCENARIOS))
    im = ax[0].imshow(pv.values.astype(float), vmin=0.5, vmax=1, cmap="viridis", aspect="auto"); ax[0].set_xticks(range(3)); ax[0].set_xticklabels(pv.columns)
    ax[0].set_yticks(range(len(pv))); ax[0].set_yticklabels(pv.index, fontsize=7); ax[0].set_title("F1 by scenario x protocol"); ax[0].grid(False); fig.colorbar(im, ax=ax[0])
    for mname, c in (("standard", "#c0392b"), ("pgd_trained", "#1f77b4")):
        s = pg[pg.model == mname]; ax[1].plot(s.pgd_eps, s.acc, "o-", label=mname, color=c)
        e = ev[ev.model == mname]; ax[2].plot(e.blend, e.detection_rate, "s-", label=mname, color=c)
    ax[1].set_xlabel("PGD eps (std units)"); ax[1].set_ylabel("accuracy"); ax[1].legend(); ax[1].set_title("Adversarial robustness")
    ax[2].set_xlabel("blend toward tunnel (1 = unmodified)"); ax[2].set_ylabel("detection rate"); ax[2].set_title("S5 evasion by blending"); ax[2].legend()
    savefig(fig, "e1_e9_detection_adversarial"); return g, sw, pg, ev

if __name__ == "__main__":
    g, sw, pg, ev = run(); print(g.round(3).to_string()); print(sw.round(3)); print(pg.round(3)); print(ev.round(3))
