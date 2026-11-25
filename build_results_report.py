#!/usr/bin/env python3
"""Generate docs/v2/09_harness_results.md from results_v2/tables/*.csv so that text and numbers cannot drift apart."""
import os, json
import pandas as pd
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
T = lambda n: pd.read_csv(os.path.join(ROOT, "results_v2", "tables", n + ".csv"))
def md(df, fmt=".3f"):
    return df.to_markdown(index=False, floatfmt=fmt)
meta = json.load(open(os.path.join(ROOT, "results_v2", "run_metadata.json")))
e1 = T("e1_per_scenario_protocol"); sw = T("e1_severity_sweep"); pg = T("e9_pgd_robustness"); ev = T("e9_evasion_blend")
by = T("e2_byzantine_sweep"); dp = T("e3_dp_sweep"); ng = T("e4_noise_growth"); sm = T("e4_sampler_benchmark"); ol = T("e4_operation_latency"); eh = T("e4_encrypted_histogram"); so = T("e4_selective_operations")
kq = T("e5_key_stream_quality"); cc = T("e5_controller_cost"); sc = T("e5_side_channel_tradeoff"); se = T("e5_se3_exponential")
ab = T("e6_factorial_ablation"); me = T("e6_main_effects"); pol = T("e7_policy_rollouts"); fu = T("e8_intel_fusion"); th = T("e8_intel_throughput"); cm = T("e10_case_matrix_wide")
cm_all = T("e10_attack_case_matrix")

first_fail = ng[ng.max_abs_noise.isna()].set_index("params").additions_plus1
g40 = by[(by.byz_frac == 0.4) & (by.attack == "gradient_flip")].set_index("method").f1
p_std = pg[pg.model == "standard"].set_index("pgd_eps").acc; p_at = pg[pg.model == "pgd_trained"].set_index("pgd_eps").acc
dp_ = dp.set_index("eps_target"); fu_ = fu[(fu.threshold == 0.5)].set_index("source")
sc0, sc_hi = sc.iloc[0], sc.iloc[-1]
cmb = cm[["baseline", "low_and_slow", "adaptive_blend"]].mean()
so_ = so.set_index("features_encrypted")
fl_on = ab[(ab.FL == 1)].f1_20pct_byz.iloc[0]; fl_off = ab[(ab.FL == 0)].f1_20pct_byz.iloc[0]

out = f"""# 09. Harness results (synthetic simulation)

> **Every number in this document is produced by the v2 harness on synthetic data.** None of it is a testbed measurement. The testbed values of Chapter 6 are in `07_thesis_reported_results.md`. Host: {meta['machine']}, {meta['cores']} core(s), Python {meta['python']}, NumPy {meta['numpy']}; seeds {meta['seeds']}; total run time {meta['total_seconds']} s. Reproduce with `make -f Makefile.v2 results`.

The harness is meant to show the direction and size of effects for each Chapter 6 mechanism and to give the testbed runs a specification to follow. Its absolute values are lower than the thesis values because the synthetic attack classes overlap on purpose; we did not tune them to match.

## 9.1 Detection by scenario and protocol (E1)

Detector: one-hidden-layer MLP (16 units) trained on standardised features, five seeds. Averaged over all scenario and protocol cells the F1 is {e1.f1.mean():.3f}. The easiest cells are the handshake and tunnelling scenarios (for example DoT-RENEG F1 {e1[e1.scenario=='DoT-RENEG'].f1.iloc[0]:.3f}, S2-Tunnel on DoT {e1[(e1.scenario=='S2-Tunnel')&(e1.protocol=='DoT')].f1.iloc[0]:.3f}); the hardest are the timing and evasion scenarios (S1-Timing F1 {e1[e1.scenario=='S1-Timing'].f1.iloc[0]:.3f}, S5-Evasion on DoH {e1[(e1.scenario=='S5-Evasion')&(e1.protocol=='DoH')].f1.iloc[0]:.3f}). This ordering follows the way Chapter 6 describes the scenarios: timing statistics and adversarially shaped queries stay closest to benign traffic.

![detection and adversarial robustness](../../results_v2/figures/e1_e9_detection_adversarial.png)

{md(e1)}

Severity sweep (detector trained at severity 1.0):

{md(sw)}

Recall falls from {sw.recall.iloc[3]:.2f} at severity 1.0 to {sw.recall.iloc[0]:.2f} at severity 0.25, so a detector trained on full-strength attacks misses weak ones. The benign false-positive rate is the same in every row because the benign sample is the same.

## 9.2 Adversarial robustness (E9)

L-infinity PGD in standardised feature units. At epsilon = 0.3 (the value of Table 30) the standard detector has accuracy {p_std[0.3]:.3f} and the PGD-trained detector {p_at[0.3]:.3f}; on clean data the standard detector has accuracy {p_std[0.0]:.3f} and the PGD-trained one {p_at[0.0]:.3f}. Adversarial training buys robustness at a cost in clean accuracy and false positives.

{md(pg)}

Blending attack (the attacker moves tunnel statistics toward benign by a factor; 1.0 is unmodified):

{md(ev)}

Blending to 40 % of the tunnel shift drops detection of the DoH tunnel to {ev[(ev.model=='standard')&(ev.blend==0.4)].detection_rate.iloc[0]:.2f} for the standard detector; the PGD-trained detector is not better against this attack ({ev[(ev.model=='pgd_trained')&(ev.blend==0.4)].detection_rate.iloc[0]:.2f}), because blending moves along the benign direction and not along the gradient.

## 9.3 Byzantine aggregation (E2)

K = 50 clients, 40 rounds, three seeds, update clipping at 2.0 for every aggregator. Under 40 % gradient-flipping clients the F1 is {g40['mean']:.3f} for the plain mean, {g40['median']:.3f} for the coordinate median, {g40['geomed']:.3f} for the geometric median and {g40['mad_geomed']:.3f} for the MAD filter followed by the geometric median. The MAD filter keeps the F1 at the level of the attack-free run ({by[(by.byz_frac==0)&(by.method=='mad_geomed')].f1.iloc[0]:.3f}).

![Byzantine sweep](../../results_v2/figures/e2_byzantine_sweep.png)

Two caveats. The `backdoor_scale` attack multiplies an honest update by 10; after clipping it only changes the step size and not its direction, so it is not harmful here and is not a real backdoor. A trigger-based backdoor needs its own experiment. The MAD filter also assumes that malicious updates are far from the median; the adaptive attack that stays under the cut-off is listed as open question Q5.

{md(by)}

## 9.4 Differential privacy (E3)

K = 100, 100 rounds, Gaussian mechanism, RDP accounting without sub-sampling amplification, delta = 1e-5.

{md(dp)}

At epsilon = 0.68 the F1 is {dp_.loc[0.68].f1:.3f} against {dp_.loc[float('inf')].f1:.3f} without noise, a drop of {dp_.loc[float('inf')].f1 - dp_.loc[0.68].f1:.3f}. Chapter 6 reports about 0.4 percentage points. The gap most likely comes from the missing sampling amplification and from the small detector; we list it as open question Q2 and do not treat it as a refutation. The noise multiplier needed for each (epsilon, rounds) pair is in `results_v2/tables/e3_dp_calibration_grid.csv`.

![DP accountant](../../results_v2/figures/e3_dp_accountant.png)

## 9.5 Homomorphic layer (E4)

Toy parameters. Plaintext modulus is 2 for the two sets named after the thesis tables and 256 for the NTT-friendly set, so their noise budgets are not directly comparable.

- **Noise budget (E4a).** With repeated addition of fresh ciphertexts, decryption first fails after {int(first_fail['thesis_table27'])} summands for the Table 27 set (n = 1024, q = 3329), {int(first_fail['thesis_table34a'])} for the Table 34a set (n = 256, q = 4096) and {int(first_fail['ntt_n256'])} for the NTT set (n = 256, q = 786433). The encrypted-histogram aggregation of Section 6.5.3 therefore needs a stated bound on the number of reporters.
- **Samplers (E4b).** Both samplers match the target distribution (chi-square p = {sm.chi2_p.iloc[0]:.2f} and {sm.chi2_p.iloc[1]:.2f}); the table-driven one is {sm.msamples_per_s.iloc[0] / sm.msamples_per_s.iloc[1]:.1f}x faster than rejection sampling in this NumPy setting.
- **Encrypted histograms (E4e).** {int(eh.reporters.iloc[0])} reporters x {int(eh.window.iloc[0])} queries per aggregate. The decrypted aggregate equals the plaintext histogram in {eh.exact_match_rate.iloc[0]*100:.0f} % of trials. The chi-square test separates benign from tunnel-like windows with AUC {eh.auc_chi2_decrypted_aggregate.iloc[0]:.2f}; an adversary that sees only ciphertext coefficients reaches AUC {eh.auc_ciphertext_only_adversary.iloc[0]:.2f}, which is chance.
- **Selective operations (E4f).** Processing 2 of 16 features gives an 8x reduction in encrypted values and F1 {so_.loc[2].f1:.3f}, against {so_.loc[16].f1:.3f} for all 16. The reduction has a price in detection quality; Chapter 6 reports the factor 8 without that price.
- **Latency and size (E4d).** Single-threaded NumPy: encrypt {ol.encrypt_ms.iloc[2]:.2f} ms, add {ol.add_ms.iloc[2]:.3f} ms, decrypt {ol.decrypt_ms.iloc[2]:.3f} ms for n = 256. These are host timings and say nothing about the 28x speedup of the optimised implementation.

![noise growth](../../results_v2/figures/e4_noise_growth.png)

{md(ng.fillna(''), '.4f')}

## 9.6 Adaptive evolutionary encryption (E5)

- **SE(3) update (E5a).** The closed-form exponential agrees with `scipy.linalg.expm` to {se.max_abs_error_vs_expm.iloc[0]} over {int(se.twists.iloc[0])} random twists, and every result is a rigid transform.
- **Key stream screening (E5b).** {int(kq['keys'].iloc[0])} keys, {int(kq['unique_keys'].iloc[0])} unique; mean Hamming distance between consecutive keys {kq.mean_hamming_consecutive.iloc[0]:.1f} of 256 (ideal 128); Shannon entropy {kq.shannon_bits_per_byte.iloc[0]:.4f} bits per byte; min-entropy {kq.min_entropy_bits_per_byte.iloc[0]:.2f} bits per byte; mean rotation cadence {kq.mean_cadence_s.iloc[0]:.1f} s (range {kq.min_cadence_s.iloc[0]:.1f} to {kq.max_cadence_s.iloc[0]:.1f}). This is statistical screening and not a security argument; Chapter 6 makes no IND-CCA2 claim for the schedule.
- **Controller cost (E5e).** The 2 x 64 controller has {int(cc.params.iloc[0])} parameters. int8 weight rounding changes outputs by at most {cc.max_abs_dev_vs_fp64.iloc[1]:.3f}; it gives no speed-up in NumPy because the weights are rounded and not executed in integer arithmetic. The complete update (controller, SDE step, SE(3), HKDF) takes {cc.median_us.iloc[3]:.0f} microseconds median in NumPy, against the 45 microseconds of the optimised path in Chapter 6.
- **Timing side channel (E5f).** An observer who tries to tell cache hits from misses using eight inter-arrival times per window has AUC {sc0.adversary_auc:.2f} without jitter. With mean added delay {sc_hi.mean_added_delay_ms:.0f} ms the AUC falls to {sc_hi.adversary_auc:.2f}. The curve is not monotone at the smallest setting (the first nonzero point is within noise of the baseline). Protection from timing jitter has a latency price that grows linearly, which is the trade-off Q4 asks the testbed to measure.

![side channel](../../results_v2/figures/e5_side_channel_tradeoff.png)

![key stream](../../results_v2/figures/e5_key_stream.png)

## 9.7 Ablation (E6)

{md(ab)}

Robust federated training improves F1 under 20 % malicious clients from {fl_off:.3f} (local-only) to {fl_on:.3f}. The timing adversary's AUC falls with AEE jitter and the analyzer's view falls to chance with QHE. The added delay is dominated by the jitter. In this harness the three components act on separate quantities, so interaction terms are zero by construction; whether integration produces more than the sum is the question the testbed ablation of `06_evaluation_protocol.md` must answer.

![ablation](../../results_v2/figures/e6_factorial_ablation.png)

## 9.8 Sandbox policy (E7)

{md(pol)}

The optimal policy from value iteration has lower expected cost than always allowing or only monitoring, and lower than always terminating. Which action is optimal in the suspicious state depends on the escalation probability and the cost of staying isolated (`e7_policy_sensitivity.csv`): with a low escalation probability the policy allows, with a moderate isolation cost it isolates, and with a high isolation cost it terminates. This is a property of our small MDP.

## 9.9 Threat intelligence (E8)

At threshold 0.5 the fused noisy-OR score reaches recall {fu_.loc['fused (noisy-OR)'].recall:.2f} at precision {fu_.loc['fused (noisy-OR)'].precision:.2f}; the best single source reaches recall {fu_.drop('fused (noisy-OR)').recall.max():.2f}. Fusion helps because the feeds cover different parts of the malicious set. Parsing and fusing 1,000 indicators takes {th.seconds.iloc[0]*1000:.1f} ms, inside the 100 ms bound of Section 6.7.1; 100,000 indicators take {th.seconds.iloc[2]:.2f} s.

![intel](../../results_v2/figures/e8_intel.png)

## 9.10 Attack-case matrix (E10)

Recall at a 5 % benign false-positive operating point. Averaged over all cases: {cmb['baseline']:.2f} for the baseline variant, {cmb['low_and_slow']:.2f} for low-and-slow and {cmb['adaptive_blend']:.2f} for adaptive blending.

![case matrix](../../results_v2/figures/e10_attack_case_matrix.png)

{md(cm)}

Every scenario loses recall when the attacker weakens or blends the attack. The scenarios that lose most are those that were already weakest at baseline (S1-Timing, S5-Evasion, DoH multiplexing). S2-Tunnel keeps recall above 0.6 in both weakened variants on all three protocols.

## 9.11 What these results do and do not support

Supported by the harness: robust aggregation resists a minority of sign-flipping clients; adversarial training trades clean accuracy for robustness; ciphertext-only observers learn nothing useful from the encrypted histograms while an authorised party decrypts exact counts; timing jitter lowers an observer's accuracy at a measurable latency cost; fusing feeds raises recall.

Not supported or not tested: any absolute accuracy, latency or throughput of Chapter 6; the cost of epsilon = 0.68 on the real detector; whether the three components together outperform their separate effects; security of the lattice parameters.
"""
with open(os.path.join(ROOT, "docs", "v2", "09_harness_results.md"), "w") as f: f.write(out)
print("report written", len(out))
