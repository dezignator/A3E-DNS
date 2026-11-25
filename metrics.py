"""Metrics of Sections 6.9.1 (Eq. 131), 6.10 (Eqs. 134-135) and the statistics used in Section 6.16."""
import numpy as np
from scipy import stats

# ---- Eq. (131): CDS = 2 * AUPRC * F1w / (AUPRC + F1w) - lambda * D_JS(P_benign || P_detected)
def auprc(y, s):
    o = np.argsort(-s); y = np.asarray(y)[o]; tp = np.cumsum(y == 1); fp = np.cumsum(y == 0)
    prec = tp / np.maximum(tp + fp, 1); rec = tp / max((y == 1).sum(), 1)
    return float(np.sum(np.diff(np.concatenate([[0], rec])) * prec))          # average precision (step interpolation)

def weighted_f1(y, yhat):
    y = np.asarray(y); yhat = np.asarray(yhat); tot = 0.0
    for c in (0, 1):
        tp = ((yhat == c) & (y == c)).sum(); fp = ((yhat == c) & (y != c)).sum(); fn = ((yhat != c) & (y == c)).sum()
        f = 2 * tp / max(2 * tp + fp + fn, 1); tot += f * (y == c).sum()
    return float(tot / len(y))

def jsd(p, q, eps=1e-12):
    p = np.asarray(p, float) + eps; q = np.asarray(q, float) + eps; p /= p.sum(); q /= q.sum(); m = 0.5 * (p + q)
    return float(0.5 * np.sum(p * np.log(p / m)) + 0.5 * np.sum(q * np.log(q / m)))

def cds(y, score, yhat, lam=0.1, bins=20):
    """Eq. (131). The chapter does not fix the two sample sets of the JSD term; we take
    P_benign = histogram of detector scores over ground-truth benign flows and
    P_detected = histogram of detector scores over flows the detector accepted as benign (yhat = 0).
    This reading is documented in docs/v2/08_consistency_audit.md."""
    y = np.asarray(y); a, f = auprc(y, score), weighted_f1(y, yhat); h = 2 * a * f / max(a + f, 1e-12)
    edges = np.linspace(0, 1, bins + 1); pb = np.histogram(score[y == 0], edges)[0]; pd_ = np.histogram(score[np.asarray(yhat) == 0], edges)[0]
    return float(h - lam * jsd(pb, pd_)), dict(auprc=a, f1_weighted=f, jsd=jsd(pb, pd_))

# ---- Eqs. (134)-(135)
def eta_adversarial(D, gamma, delta):
    """Eq. (135): share of events whose impact D(tau_i) exceeds gamma * delta_i."""
    return float(np.mean(np.asarray(D) > gamma * np.asarray(delta)))

def qps_max(b_mem, e_tau, c_cpu, e_t_process, b_net, e_s_packet, eta=0.0):
    """Eq. (134): min(memory, CPU, network bound) * (1 - eta_adversarial). Units must be consistent."""
    return float(min(b_mem / e_tau, c_cpu / e_t_process, b_net / e_s_packet) * (1 - eta))

# ---- statistics
def bootstrap_ci(x, f=np.mean, n=2000, alpha=0.05, seed=0):
    r = np.random.default_rng(seed); x = np.asarray(x); s = [f(r.choice(x, len(x))) for _ in range(n)]
    return float(f(x)), float(np.quantile(s, alpha / 2)), float(np.quantile(s, 1 - alpha / 2))

def cohens_d(a, b):
    a, b = np.asarray(a), np.asarray(b); sp = np.sqrt(((len(a) - 1) * a.var(ddof=1) + (len(b) - 1) * b.var(ddof=1)) / (len(a) + len(b) - 2))
    return float((a.mean() - b.mean()) / max(sp, 1e-12))

def welch(a, b):
    t, p = stats.ttest_ind(a, b, equal_var=False); return float(t), float(p)

def mcnemar(correct_a, correct_b):
    a = np.asarray(correct_a, bool); b = np.asarray(correct_b, bool); n01 = int((~a & b).sum()); n10 = int((a & ~b).sum())
    if n01 + n10 == 0: return 0.0, 1.0
    chi = (abs(n01 - n10) - 1)**2 / (n01 + n10); return float(chi), float(1 - stats.chi2.cdf(chi, 1))

def holm(pvals):
    """Holm-Bonferroni adjusted p-values (for the multiple comparisons of an ablation)."""
    p = np.asarray(pvals, float); o = np.argsort(p); m = len(p); adj = np.empty(m); run = 0.0
    for rank, i in enumerate(o): run = max(run, (m - rank) * p[i]); adj[i] = min(run, 1.0)
    return adj

def roc_auc(y, s):
    o = np.argsort(s); r = np.empty(len(s)); r[o] = np.arange(1, len(s) + 1)
    n1 = (y == 1).sum(); n0 = (y == 0).sum(); return float((r[y == 1].sum() - n1 * (n1 + 1) / 2) / (n1 * n0))

def scorecard(acc, fpr, p99_ms, qps_m, adv, eps, weights=None):
    """NOT Eq. (131). A six-factor summary we use only to rank configurations in the dashboard.
    Mapping to [0,1]: latency 1 at <=1 ms and 0 at >=10 ms; throughput 1 at 25 M QPS; privacy 1 at eps<=1 and 0 at eps>=8."""
    w = weights or [0.25, 0.15, 0.15, 0.15, 0.20, 0.10]
    lat = np.clip((10 - p99_ms) / 9, 0, 1); thr = np.clip(qps_m / 25, 0, 1); prv = np.clip((8 - eps) / 7, 0, 1)
    return float(np.dot(w, [acc, 1 - fpr, lat, thr, adv, prv]))
