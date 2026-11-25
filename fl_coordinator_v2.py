"""Command-line federated training run on the synthetic generator (Section 6.6). Writes a JSON summary."""
import argparse, json, os
from common import *
from e2_federated import one

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--clients", type=int, default=100); ap.add_argument("--rounds", type=int, default=100)
    ap.add_argument("--aggregator", default="mad_geomed", choices=["mean", "median", "trimmed", "geomed", "mad_geomed"]); ap.add_argument("--byz-frac", type=float, default=0.0)
    ap.add_argument("--attack", default="none"); ap.add_argument("--dp-epsilon", type=float, default=None); ap.add_argument("--seed", type=int, default=11); ap.add_argument("--out", default=os.path.join(LOG, "fl_run.json"))
    a = ap.parse_args(); r, sim = one(a.seed, a.clients, a.rounds, a.byz_frac, a.attack, a.aggregator, a.dp_epsilon)
    out = dict(args=vars(a), metrics={k: float(v) for k, v in r.items()}, sigma=sim.sigma, epsilon_spent=sim.epsilon(), banner=BANNER)
    json.dump(out, open(a.out, "w"), indent=2); print(json.dumps(out, indent=2))
