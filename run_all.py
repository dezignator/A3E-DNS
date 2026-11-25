"""Run every v2 experiment and write results_v2/ (tables, figures, run_metadata.json)."""
import json, os, time
from common import *
import e1_detection, e2_federated, e4_qhe, e5_aee, e6_ablation, e7_sandbox, e8_intel, e10_case_matrix

def main():
    t0 = time.time(); steps = []
    def run(name, fn, *a, **k):
        t = time.time(); fn(*a, **k); steps.append(dict(step=name, seconds=round(time.time() - t, 1))); print(f"[{name}] {steps[-1]['seconds']} s", flush=True)
    run("E1+E9 detection and adversarial", e1_detection.run)
    run("E2 Byzantine sweep", e2_federated.byzantine)
    run("E3 DP sweep (K=100, 100 rounds)", e2_federated.dp_sweep, 100, 100)
    for f in (e4_qhe.noise_growth, e4_qhe.sampler_bench, e4_qhe.ntt_bench, e4_qhe.op_latency, e4_qhe.encrypted_histogram, e4_qhe.selective_ops): run("E4 " + f.__name__, f)
    for f in (e5_aee.se3_check, e5_aee.key_quality, e5_aee.sigma_curve, e5_aee.controller_cost, e5_aee.side_channel): run("E5 " + f.__name__, f)
    run("E6 ablation", e6_ablation.run); run("E7 sandbox", e7_sandbox.run); run("E8 intel", e8_intel.run); run("E10 attack-case matrix", e10_case_matrix.run)
    with open(os.path.join(ROOT, "results_v2", "run_metadata.json"), "w") as f: json.dump(meta(dict(steps=steps, total_seconds=round(time.time() - t0, 1))), f, indent=2)
    print("done", round(time.time() - t0, 1), "s")

if __name__ == "__main__": main()
