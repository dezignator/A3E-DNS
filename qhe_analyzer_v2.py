"""Command-line encrypted-histogram demonstration (Section 6.5.3)."""
import argparse
from common import *
from a3e_dns_v2.qhe import PARAM_SETS, RLWEAdditive, EncryptedHistogram, chi_square_from_counts

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--params", default="ntt_n256", choices=list(PARAM_SETS)); ap.add_argument("--reporters", type=int, default=10); ap.add_argument("--window", type=int, default=25)
    a = ap.parse_args(); ps = PARAM_SETS[a.params]; assert a.reporters * a.window < ps.t, "aggregate counts must stay below the plaintext modulus"
    sc = RLWEAdditive(ps, 1); eh = EncryptedHistogram(sc, np.linspace(0, 6, 17)); r = np.random.default_rng(0)
    base = np.histogram(r.normal(3.1, 0.35, 100000), bins=eh.edges)[0].astype(float)
    for label, (mu, sd) in (("benign", (3.1, 0.35)), ("tunnel-like", (4.6, 0.8))):
        vals = [np.clip(r.normal(mu, sd, a.window), 0, 5.99) for _ in range(a.reporters)]
        dec = eh.open(eh.aggregate([eh.report(v) for v in vals])); print(f"{label:12s} chi2={chi_square_from_counts(dec, base):8.2f} counts={dec.tolist()}")
