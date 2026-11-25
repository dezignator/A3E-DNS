"""E5: AEE key-stream quality, diffusion schedule, controller cost, timing side-channel trade-off (Section 6.4)."""
from common import *
import time
from scipy.linalg import expm
from a3e_dns_v2.aee import *
from a3e_dns_v2.aee.se3 import hat, exp_se3, is_rigid
from a3e_dns_v2.aee.entropy import shannon_bits
from a3e_dns_v2.metrics import roc_auc

def se3_check(n=2000):
    r = np.random.default_rng(0); err = 0; rig = True
    for _ in range(n):
        xi = r.standard_normal(6) * r.choice([1e-6, 0.1, 1, 3]); T1 = exp_se3(xi); T2 = expm(hat(xi)); err = max(err, np.abs(T1 - T2).max()); rig &= is_rigid(T1, 1e-7)
    df = pd.DataFrame([dict(twists=n, max_abs_error_vs_expm=f"{err:.2e}", all_rigid=rig)]); save_table(df, "e5_se3_exponential", "E5a. Closed-form se(3) exponential versus scipy.linalg.expm"); return df

def key_quality(nkeys=3000, seed=9):
    e = AEEEngine(seed=seed); r = np.random.default_rng(seed); keys = []; cad = []; sig = []
    base = np.array([5, 4, 3, 2, 2, 1.], float)
    for i in range(nkeys):
        f = r.standard_normal(16); p = base * (1 + 0.3 * r.standard_normal(6).clip(-1, 1) * (1 if i % 500 < 400 else 4)); p = np.abs(p) + 0.01
        k, iv, c, rec = e.update(f, p, base); keys.append(k); cad.append(c); sig.append(rec["sigma"])
    bits = np.unpackbits(np.frombuffer(b"".join(keys), np.uint8)).reshape(nkeys, 256)
    ham = (bits[1:] != bits[:-1]).sum(1); allb = bits.ravel(); mono = abs(allb.mean() - 0.5)
    runs = 1 + (allb[1:] != allb[:-1]).sum(); z_runs = (runs - len(allb) / 2) / (np.sqrt(len(allb)) / 2)
    byts = b"".join(keys); counts = np.bincount(np.frombuffer(byts, np.uint8), minlength=256); pmax = counts.max() / counts.sum()
    df = pd.DataFrame([dict(keys=nkeys, unique_keys=len(set(keys)), mean_hamming_consecutive=ham.mean(), sd_hamming=ham.std(), ideal_hamming=128, monobit_dev=mono,
                            runs_z=z_runs, shannon_bits_per_byte=shannon_bits(byts), min_entropy_bits_per_byte=-np.log2(pmax), mean_cadence_s=float(np.mean(cad)), min_cadence_s=float(np.min(cad)), max_cadence_s=float(np.max(cad)))])
    save_table(df, "e5_key_stream_quality", "E5b. Statistical screening of derived 256-bit keys (a screening, not a cryptographic proof)")
    fig, ax = plt.subplots(1, 3, figsize=(10.5, 2.9))
    ax[0].hist(ham, bins=40, color="#2c7fb8"); ax[0].axvline(128, color="k", ls=":"); ax[0].set_xlabel("Hamming distance of consecutive keys"); ax[0].set_title("Avalanche screening")
    ax[1].hist(cad, bins=30, color="#1a9850"); ax[1].set_xlabel("rotation cadence (s)"); ax[1].set_title("Cadence distribution")
    ax[2].plot(sig, lw=0.6); ax[2].set_xlabel("update"); ax[2].set_ylabel("sigma"); ax[2].set_title("Diffusion over KL bursts"); savefig(fig, "e5_key_stream"); return df

def sigma_curve():
    kls = np.linspace(0, 1.2, 25); s = [sigma_from_kl(k) for k in kls]
    df = pd.DataFrame(dict(kl=kls, sigma=s)); save_table(df, "e5_sigma_vs_kl", "E5c. Diffusion level as a function of KL divergence (Eq. 120 sigmoid, kl0=0.3)")
    g = np.linspace(0, 3, 13); d2 = pd.DataFrame(dict(cum_grad2=g, Sigma_s_min_0p05_s_max_0p3=[diffusion_coefficient(x, 0.05, 0.3) for x in g]))
    save_table(d2, "e5_diffusion_schedule", "E5d. Eq. (122): diffusion decays toward s_min as accumulated gradient energy grows")
    fig, ax = plt.subplots(1, 2, figsize=(7.5, 2.9)); ax[0].plot(kls, s); ax[0].axvline(0.3, ls=":", color="gray"); ax[0].set_xlabel("KL divergence"); ax[0].set_ylabel("sigma")
    ax[1].plot(g, d2.iloc[:, 1]); ax[1].set_xlabel("accumulated gradient energy"); ax[1].set_ylabel("Sigma"); savefig(fig, "e5_sigma_schedule"); return df

def controller_cost(reps=300):
    c = NeuralController(); c.fit_normaliser(np.random.default_rng(0).standard_normal((100, 16))); x = np.random.default_rng(1).standard_normal(16); out = []
    for variant in ("fp64", "int8_weights", "int8_pruned30"):
        cc = NeuralController(); cc.mu, cc.sd = c.mu, c.sd
        if variant != "fp64": cc.quantize_int8()
        if variant == "int8_pruned30": cc.prune(0.3)
        ref = c(x); ts = []
        for _ in range(reps): t0 = time.perf_counter(); y = cc(x); ts.append((time.perf_counter() - t0) * 1e6)
        out.append(dict(variant=variant, params=cc.n_params(), median_us=np.median(ts), p99_us=np.percentile(ts, 99), max_abs_dev_vs_fp64=float(np.abs(y - ref).max())))
    e = AEEEngine(seed=1); f = np.random.default_rng(2).standard_normal(16); ts = []
    for _ in range(reps): t0 = time.perf_counter(); e.update(f, [5, 4, 3, 2], [4, 4, 3, 3]); ts.append((time.perf_counter() - t0) * 1e6)
    out.append(dict(variant="full AEE update (controller + SDE + SE3 + HKDF)", params=e.ctrl.n_params(), median_us=np.median(ts), p99_us=np.percentile(ts, 99), max_abs_dev_vs_fp64=np.nan))
    df = pd.DataFrame(out); save_table(df, "e5_controller_cost", "E5e. Controller and full update cost in NumPy on the host in run_metadata.json (the 45 microsecond figure in Chapter 6 refers to the optimised C path)"); return df

def window_stats(rng, state, n=8, k=0.0, sigma=0.12):
    mu, sd = {0: (30.0, 14.0), 1: (36.0, 15.0)}[state]
    x = np.abs(rng.normal(mu, sd, n)); delay = np.abs(rng.normal(0, k * sigma, n)) if k > 0 else np.zeros(n); y = x + delay
    return [y.mean(), y.std(), float(((y - y.mean())**3).mean() / (y.std()**3 + 1e-9))], delay.mean()

def side_channel(seeds=SEEDS):
    rows = []
    for s in seeds:
        r = np.random.default_rng(s)
        for k in (0, 40, 80, 160, 320, 640):
            X, y, dl = [], [], []
            for i in range(1600):
                st = i % 2; f, d = window_stats(r, st, k=k); X.append(f); y.append(st); dl.append(d)
            X, y = np.array(X), np.array(y); mu, sd = X[:800].mean(0), X[:800].std(0) + 1e-9; Z = (X - mu) / sd
            m = fit_logreg(Z[:800], y[:800].astype(float), epochs=1200, hidden=8, seed=s); p = m.predict_proba(Z[800:])
            rows.append(dict(seed=s, k_ms_per_sigma=k, adversary_auc=roc_auc(y[800:], p), adversary_acc=float(((p > 0.5) == y[800:]).mean()), mean_added_delay_ms=float(np.mean(dl))))
    df = pd.DataFrame(rows).groupby("k_ms_per_sigma").agg(adversary_auc=("adversary_auc", "mean"), auc_sd=("adversary_auc", "std"), adversary_acc=("adversary_acc", "mean"), mean_added_delay_ms=("mean_added_delay_ms", "mean")).reset_index()
    save_table(df, "e5_side_channel_tradeoff", "E5f. Timing side-channel adversary (cache-hit vs miss) against AEE-driven timing jitter: adversary AUC against mean added delay (sigma=0.12)")
    fig, ax = plt.subplots(figsize=(4.4, 3.2)); ax.plot(df.mean_added_delay_ms, df.adversary_auc, "o-"); ax.axhline(0.5, ls=":", color="gray")
    for _, r_ in df.iterrows(): ax.annotate(f"k={int(r_.k_ms_per_sigma)}", (r_.mean_added_delay_ms, r_.adversary_auc), fontsize=6, xytext=(3, 3), textcoords="offset points")
    ax.set_xlabel("mean added delay (ms)"); ax.set_ylabel("adversary AUC"); ax.set_title("Privacy versus latency"); savefig(fig, "e5_side_channel_tradeoff"); return df

if __name__ == "__main__":
    for f in (se3_check, key_quality, sigma_curve, controller_cost, side_channel):
        d = f(); print(f.__name__); print(d.round(4).to_string()); print()
