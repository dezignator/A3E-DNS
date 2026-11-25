"""E4: QHE structure, noise growth, sampler, NTT, encrypted analytics, selective operations (Section 6.5)."""
from common import *
import time
from a3e_dns_v2.qhe import *
from a3e_dns_v2.qhe.ring import negacyclic_mul
from a3e_dns_v2.metrics import roc_auc
from scipy import stats

def noise_growth():
    rows = []
    for name, ps in PARAM_SETS.items():
        sc = RLWEAdditive(ps, seed=5); r = np.random.default_rng(5)
        m0 = r.integers(0, ps.t, ps.n); acc = sc.encrypt(m0); mexp = m0.copy(); k = 1; fail_at = None; trace = {}
        while k <= 4096:
            if k in (1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096): trace[k] = sc.noise(acc, mexp)
            if not np.array_equal(sc.decrypt(acc), mexp): fail_at = k; break
            m = r.integers(0, ps.t, ps.n); acc = sc.add(acc, sc.encrypt(m)); mexp = (mexp + m) % ps.t; k += 1
        for kk, v in trace.items(): rows.append(dict(params=name, n=ps.n, q=ps.q, t=ps.t, delta=ps.delta, additions_plus1=kk, max_abs_noise=v, half_delta=ps.delta // 2, ratio=v / (ps.delta // 2)))
        rows.append(dict(params=name, n=ps.n, q=ps.q, t=ps.t, delta=ps.delta, additions_plus1=-1 if fail_at is None else fail_at, max_abs_noise=np.nan, half_delta=ps.delta // 2, ratio=np.nan))
    df = pd.DataFrame(rows); save_table(df, "e4_noise_growth", "E4a. Noise growth under repeated ciphertext addition (additions_plus1 = -1 means no failure up to 4096; a row with max_abs_noise NaN gives the first failing count)")
    fig, ax = plt.subplots(figsize=(4.6, 3.2))
    for name in PARAM_SETS:
        s = df[(df.params == name) & df.max_abs_noise.notna()]; ax.loglog(s.additions_plus1, s.max_abs_noise, "o-", label=name)
        ax.axhline(s.half_delta.iloc[0], ls=":", color="gray", lw=0.8)
    ax.set_xlabel("ciphertexts summed"); ax.set_ylabel("max |noise|"); ax.legend(fontsize=7); ax.set_title("Noise vs additions (dotted = delta/2)"); savefig(fig, "e4_noise_growth"); return df

def sampler_bench(N=400_000):
    rows = []
    for nm, cls in (("table_cdt", TableGaussianSampler), ("rejection", RejectionGaussianSampler)):
        s = cls(1.58, seed=1); t0 = time.perf_counter(); x = s.sample(N); dt = time.perf_counter() - t0
        vals, cnt = np.unique(x, return_counts=True); B = 12; ex = np.exp(-vals**2 / (2 * 1.58**2)); ex = ex / ex.sum() * N; m = ex > 5
        chi = float(((cnt[m] - ex[m])**2 / ex[m]).sum()); p = float(1 - stats.chi2.cdf(chi, m.sum() - 1))
        rows.append(dict(sampler=nm, samples=N, seconds=dt, msamples_per_s=N / dt / 1e6, mean=float(x.mean()), std=float(x.std()), target_std=1.58, chi2=chi, chi2_p=p))
    df = pd.DataFrame(rows); save_table(df, "e4_sampler_benchmark", "E4b. Discrete Gaussian samplers (sigma=1.58), software timing on the host named in run_metadata.json"); return df

def ntt_bench(reps=20):
    ps = PARAM_SETS["ntt_n256"]; r = np.random.default_rng(0); a, b = r.integers(0, ps.q, ps.n), r.integers(0, ps.q, ps.n)
    t0 = time.perf_counter(); [negacyclic_mul(a, b, ps.q) for _ in range(reps)]; tc = (time.perf_counter() - t0) / reps
    t0 = time.perf_counter(); [ntt_negacyclic_mul(a, b, ps.q) for _ in range(3)]; tn = (time.perf_counter() - t0) / 3
    ok = np.array_equal(negacyclic_mul(a, b, ps.q), ntt_negacyclic_mul(a, b, ps.q))
    df = pd.DataFrame([dict(method="numpy convolution", ms=tc * 1e3, agree=ok), dict(method="pure-Python NTT", ms=tn * 1e3, agree=ok)])
    save_table(df, "e4_ntt_vs_convolution", "E4c. Negacyclic multiplication, n=256, q=786433 (the pure-Python NTT is for correctness; speed claims in the thesis refer to C/SIMD code)"); return df

def op_latency(reps=30):
    rows = []
    for name, ps in PARAM_SETS.items():
        sc = RLWEAdditive(ps, seed=2); m = np.zeros(ps.n, np.int64); m[:8] = 1
        t0 = time.perf_counter(); cts = [sc.encrypt(m) for _ in range(reps)]; te = (time.perf_counter() - t0) / reps
        t0 = time.perf_counter(); [sc.add(cts[i], cts[(i + 1) % reps]) for i in range(reps)]; ta = (time.perf_counter() - t0) / reps
        t0 = time.perf_counter(); [sc.decrypt(c) for c in cts]; td = (time.perf_counter() - t0) / reps
        bits = int(np.ceil(np.log2(ps.q))); rows.append(dict(params=name, encrypt_ms=te * 1e3, add_ms=ta * 1e3, decrypt_ms=td * 1e3, ct_bytes_int64=2 * ps.n * 8, ct_bytes_packed=2 * ps.n * bits // 8, pack_ratio=64 / bits))
    df = pd.DataFrame(rows); save_table(df, "e4_operation_latency", "E4d. Encrypt / add / decrypt latency and ciphertext size (single-threaded NumPy on the host in run_metadata.json)"); return df

def encrypted_histogram(trials=150, R=10, W=25, seed=3):
    ps = PARAM_SETS["ntt_n256"]; sc = RLWEAdditive(ps, seed=seed); edges = np.linspace(0, 6, 17); eh = EncryptedHistogram(sc, edges)
    assert R * W < ps.t, "aggregate counts must stay below t"
    r = np.random.default_rng(seed); base = np.histogram(r.normal(3.1, 0.35, 200000), bins=edges)[0].astype(float)
    chi_p, chi_e, y, leak, exact = [], [], [], [], 0
    t_enc = t_add = t_dec = 0.0
    for i in range(trials):
        lab = i % 2; mu, sd = (3.1, 0.35) if lab == 0 else (4.6, 0.8)     # tunnel-like qname entropy shifts up and spreads
        vals = [np.clip(r.normal(mu, sd, W), 0, 5.99) for _ in range(R)]
        t0 = time.perf_counter(); cts = [eh.report(v) for v in vals]; t1 = time.perf_counter(); agg = eh.aggregate(cts); t2 = time.perf_counter(); dec = eh.open(agg); t3 = time.perf_counter()
        t_enc += t1 - t0; t_add += t2 - t1; t_dec += t3 - t2
        plain = np.histogram(np.concatenate(vals), bins=edges)[0]; exact += int(np.array_equal(plain, dec))
        chi_p.append(chi_square_from_counts(plain, base)); chi_e.append(chi_square_from_counts(dec, base)); y.append(lab)
        leak.append(np.concatenate([agg.c0[:32], agg.c1[:32]]) / ps.q)
    y = np.array(y); leak = np.array(leak); half = trials // 2
    Z = (leak - leak[:half].mean(0)) / (leak[:half].std(0) + 1e-9); m = fit_logreg(Z[:half], y[:half].astype(float), epochs=1500, hidden=8)
    auc_ct = roc_auc(y[half:], m.predict_proba(Z[half:]))
    df = pd.DataFrame([dict(trials=trials, reporters=R, window=W, exact_match_rate=exact / trials, auc_chi2_plain=roc_auc(y, np.array(chi_p)), auc_chi2_decrypted_aggregate=roc_auc(y, np.array(chi_e)),
                            auc_ciphertext_only_adversary=auc_ct, enc_ms_per_report=t_enc / trials / R * 1e3, add_ms_per_aggregate=t_add / trials * 1e3, dec_ms_per_aggregate=t_dec / trials * 1e3)])
    save_table(df, "e4_encrypted_histogram", "E4e. Encrypted qname-entropy histograms: agreement with plaintext, detection AUC and ciphertext-only adversary AUC"); return df

def selective_ops(seeds=SEEDS[:3]):
    rows = []
    for s in seeds:
        D = build(s); Z, y, tr, te = D["Z"], D["y"], D["tr"], D["te"]
        for k in (16, 8, 4, 2):
            cols = select_features(Z[tr], y[tr], k) if k < 16 else np.arange(16)
            m = fit_logreg(Z[tr][:, cols], y[tr], seed=s, epochs=1500); r = prf(y[te], (m.predict_proba(Z[te][:, cols]) > 0.5).astype(int))
            rows.append(dict(seed=s, features_encrypted=k, ciphertext_reduction=16 / k, **r))
    df = pd.DataFrame(rows).groupby(["features_encrypted", "ciphertext_reduction"]).agg(f1=("f1", "mean"), recall=("recall", "mean"), fpr=("fpr", "mean"), acc=("acc", "mean")).reset_index()
    save_table(df, "e4_selective_operations", "E4f. Selective encrypted operations: detection quality when only the k most separating features are processed"); return df

if __name__ == "__main__":
    for f in (noise_growth, sampler_bench, ntt_bench, op_latency, encrypted_histogram, selective_ops):
        d = f(); print(f.__name__); print(d.round(4).to_string()); print()
