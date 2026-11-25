"""E2: Byzantine sweep. E3: differential-privacy sweep. (Sections 6.6, 6.9.3, 6.16)"""
from common import *
from a3e_dns_v2.fl.simulate import FLSimulation
from a3e_dns_v2.fl.dp import GaussianRDPAccountant, calibrate_sigma
import sys

def one(seed, K, rounds, byz_frac, attack, method, eps=None):
    D = build(seed, 250); Xs, ys = federate(D, K, seed)
    sim = FLSimulation(Xs, ys, D["mu"], D["sd"], n_byz=int(byz_frac * K), attack=attack, method=method, rounds=rounds, dp_eps=eps, seed=seed)
    sim.set_validation_norm(D["mu"], D["sd"]); te = D["te"]; sim.run(D["X"][te], D["y"][te], checkpoints=(rounds,))
    Zt = (D["X"][te] - D["mu"]) / D["sd"]; r = prf(D["y"][te], (sim.model.predict_proba(Zt) > 0.5).astype(int))
    return r, sim

def byzantine(K=50, rounds=40, seeds=SEEDS[:3]):
    rows = []
    for attack in ("gradient_flip", "label_flip", "random_noise", "backdoor_scale"):
        for frac in (0.0, 0.2, 0.4):
            for method in ("mean", "median", "geomed", "mad_geomed"):
                for s in seeds:
                    r, _ = one(s, K, rounds, frac, attack, method); rows.append(dict(attack=attack, byz_frac=frac, method=method, seed=s, **r))
    df = pd.DataFrame(rows); g = df.groupby(["attack", "byz_frac", "method"]).agg(f1=("f1", "mean"), f1_sd=("f1", "std"), fpr=("fpr", "mean"), acc=("acc", "mean")).reset_index()
    save_table(g, "e2_byzantine_sweep", f"E2. Byzantine sweep (K={K}, {rounds} rounds, {len(seeds)} seeds; 20% and 40% malicious clients)")
    fig, ax = plt.subplots(1, 4, figsize=(12, 2.8), sharey=True)
    for a, attack in zip(ax, g.attack.unique()):
        for m, c in zip(("mean", "median", "geomed", "mad_geomed"), ("#c0392b", "#e67e22", "#2c7fb8", "#1a9850")):
            s = g[(g.attack == attack) & (g.method == m)]; a.plot(s.byz_frac * 100, s.f1, "o-", label=m, color=c)
        a.set_title(attack, fontsize=8); a.set_xlabel("malicious clients (%)")
    ax[0].set_ylabel("global test F1"); ax[0].legend(fontsize=7); savefig(fig, "e2_byzantine_sweep"); return g

def dp_sweep(K=50, rounds=40, seeds=SEEDS[:3]):
    rows = []
    for eps in (None, 8.0, 4.0, 2.0, 1.0, 0.7, 0.68):
        for s in seeds:
            r, sim = one(s, K, rounds, 0.0, "none", "geomed", eps); rows.append(dict(eps_target=np.inf if eps is None else eps, sigma=sim.sigma, eps_spent=sim.epsilon(), seed=s, **r))
    df = pd.DataFrame(rows); g = df.groupby("eps_target").agg(sigma=("sigma", "first"), eps_spent=("eps_spent", "mean"), f1=("f1", "mean"), f1_sd=("f1", "std"), fpr=("fpr", "mean"), acc=("acc", "mean")).reset_index().sort_values("eps_target", ascending=False)
    save_table(g, "e3_dp_sweep", f"E3. DP sweep without sub-sampling amplification (K={K}, {rounds} rounds, delta=1e-5)")
    # accountant curves (analytic)
    T_ = np.arange(1, 201); fig, ax = plt.subplots(1, 2, figsize=(8, 3))
    for sg in (20, 40, 72, 150):
        ax[0].plot(T_, [GaussianRDPAccountant(sg).epsilon(t) for t in T_], label=f"sigma={sg}")
    ax[0].set_xlabel("rounds"); ax[0].set_ylabel("epsilon (delta=1e-5)"); ax[0].legend(fontsize=7); ax[0].set_title("RDP accountant")
    es = np.array([0.5, 0.68, 1, 2, 4, 8]); ax[1].plot(es, [calibrate_sigma(e, 100) for e in es], "o-"); ax[1].set_xscale("log"); ax[1].set_yscale("log")
    ax[1].set_xlabel("target epsilon"); ax[1].set_ylabel("required sigma (100 rounds)"); ax[1].set_title("Noise multiplier needed")
    savefig(fig, "e3_dp_accountant")
    tab = pd.DataFrame([dict(eps_target=e, rounds=r_, sigma=calibrate_sigma(e, r_)) for e in (0.68, 1, 2, 4, 8) for r_ in (20, 50, 100, 200)])
    save_table(tab, "e3_dp_calibration_grid", "E3b. Gaussian noise multiplier required per (epsilon, rounds), delta=1e-5, no sub-sampling")
    return g

if __name__ == "__main__":
    import time; t0 = time.time(); r, sim = one(11, 50, 40, 0.2, "gradient_flip", "mad_geomed"); print("one run", round(time.time() - t0, 2), "s", r)
