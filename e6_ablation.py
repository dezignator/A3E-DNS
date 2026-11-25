"""E6: 2^3 factorial ablation over {AEE, QHE, FL} (the design left open in Chapter 6 limitations)."""
from common import *
import itertools
from e2_federated import one
import e4_qhe as E4, e5_aee as E5
from a3e_dns_v2.metrics import roc_auc, welch, cohens_d

def run(seeds=SEEDS):
    # components act on separate quantities in the harness, so each quantity is measured once and assembled per configuration
    fl_clean, fl_byz, fl_byz_mean, local = [], [], [], []
    for s in seeds:
        fl_clean.append(one(s, 50, 40, 0.0, "none", "mad_geomed")[0]["f1"]); fl_byz.append(one(s, 50, 40, 0.2, "gradient_flip", "mad_geomed")[0]["f1"])
        fl_byz_mean.append(one(s, 50, 40, 0.2, "gradient_flip", "mean")[0]["f1"])
        D = build(s, 250); Xs, ys = federate(D, 1, s); Z0 = (Xs[0] - D["mu"]) / D["sd"]; m = fit_logreg(Z0, ys[0], seed=s, epochs=1500)
        local.append(prf(D["y"][D["te"]], (m.predict_proba(D["Z"][D["te"]]) > 0.5).astype(int))["f1"])
    side0 = E5.side_channel(seeds).set_index("k_ms_per_sigma"); eh = E4.encrypted_histogram(); lat = E5.controller_cost(100).iloc[-1]
    ol = E4.op_latency(10).set_index("params").loc["ntt_n256"]; qhe_ms = float(eh.enc_ms_per_report.iloc[0] + eh.add_ms_per_aggregate.iloc[0] / 10 + eh.dec_ms_per_aggregate.iloc[0] / 10)
    aee_ms = lat.median_us / 1e3
    k_on = 160; det_auc = []
    for s in seeds:
        D = build(s); m = fit_logreg(D["Z"][D["tr"]], D["y"][D["tr"]], seed=s, epochs=1500); det_auc.append(roc_auc(D["y"][D["te"]], m.predict_proba(D["Z"][D["te"]])))
    rows = []
    for aee, qhe, fl in itertools.product((0, 1), repeat=3):
        rows.append(dict(AEE=aee, QHE=qhe, FL=fl,
            f1_clean=np.mean(fl_clean) if fl else np.mean(local), f1_20pct_byz=np.mean(fl_byz) if fl else np.mean(local),
            timing_adversary_auc=float(side0.loc[k_on, "adversary_auc"] if aee else side0.loc[0, "adversary_auc"]),
            analyzer_view_auc=float(eh.auc_ciphertext_only_adversary.iloc[0] if qhe else np.mean(det_auc)),
            added_delay_ms=float(side0.loc[k_on, "mean_added_delay_ms"] if aee else 0.0) + (qhe_ms if qhe else 0.0) + (aee_ms if aee else 0.0)))
    df = pd.DataFrame(rows); df.insert(0, "config", [f"AEE={a} QHE={q} FL={f}" for a, q, f in zip(df.AEE, df.QHE, df.FL)])
    save_table(df, "e6_factorial_ablation", "E6. Full 2^3 factorial ablation (synthetic harness; components act on separate quantities, so interaction terms are zero by construction)")
    # main effects with Welch tests on per-seed values for FL
    eff = pd.DataFrame([dict(component="FL (robust aggregation vs local-only)", metric="f1 under 20% gradient-flip clients", on=np.mean(fl_byz), off=np.mean(local), welch_p=welch(fl_byz, local)[1], cohens_d=cohens_d(fl_byz, local)),
                        dict(component="Robust aggregation vs plain mean", metric="f1 under 20% gradient-flip clients", on=np.mean(fl_byz), off=np.mean(fl_byz_mean), welch_p=welch(fl_byz, fl_byz_mean)[1], cohens_d=cohens_d(fl_byz, fl_byz_mean))])
    save_table(eff, "e6_main_effects", "E6b. Paired comparisons supporting the ablation (5 seeds)")
    fig, ax = plt.subplots(1, 3, figsize=(11, 3)); lab = [f"{a}{q}{f}" for a, q, f in zip(df.AEE, df.QHE, df.FL)]
    ax[0].bar(lab, df.f1_20pct_byz, color="#2c7fb8"); ax[0].set_title("F1 under 20% malicious clients"); ax[0].set_xlabel("AEE QHE FL (1 = on)"); ax[0].set_ylim(0.5, 1)
    ax[1].bar(lab, df.timing_adversary_auc, color="#e67e22"); ax[1].axhline(0.5, ls=":", color="gray"); ax[1].set_title("Timing adversary AUC"); ax[1].set_ylim(0.4, 0.9)
    ax[2].bar(lab, df.added_delay_ms, color="#1a9850"); ax[2].set_title("Added delay (ms)"); savefig(fig, "e6_factorial_ablation"); return df, eff

if __name__ == "__main__":
    d, e = run(); print(d.round(3).to_string()); print(e.round(4).to_string())
