# 09. Harness results (synthetic simulation)

> **Every number in this document is produced by the v2 harness on synthetic data.** None of it is a testbed measurement. The testbed values of Chapter 6 are in `07_thesis_reported_results.md`. Host: x86_64, 1 core(s), Python 3.12.3, NumPy 2.5.4; seeds [11, 23, 37, 41, 59]; total run time 165.9 s. Reproduce with `make -f Makefile.v2 results`.

The harness is meant to show the direction and size of effects for each Chapter 6 mechanism and to give the testbed runs a specification to follow. Its absolute values are lower than the thesis values because the synthetic attack classes overlap on purpose; we did not tune them to match.

## 9.1 Detection by scenario and protocol (E1)

Detector: one-hidden-layer MLP (16 units) trained on standardised features, five seeds. Averaged over all scenario and protocol cells the F1 is 0.752. The easiest cells are the handshake and tunnelling scenarios (for example DoT-RENEG F1 0.851, S2-Tunnel on DoT 0.838); the hardest are the timing and evasion scenarios (S1-Timing F1 0.660, S5-Evasion on DoH 0.650). This ordering follows the way Chapter 6 describes the scenarios: timing statistics and adversarially shaped queries stay closest to benign traffic.

![detection and adversarial robustness](../../results_v2/figures/e1_e9_detection_adversarial.png)

| scenario    | protocol   |   auc |   recall |   precision |    f1 |   fpr |   f1_sd |
|:------------|:-----------|------:|---------:|------------:|------:|------:|--------:|
| DoH-HDR     | DoH        | 0.951 |    0.908 |       0.603 | 0.719 | 0.155 |   0.090 |
| DoH-MUX     | DoH        | 0.940 |    0.839 |       0.552 | 0.662 | 0.155 |   0.038 |
| DoH-RESUME  | DoH        | 0.894 |    0.804 |       0.575 | 0.663 | 0.155 |   0.042 |
| DoQ-MIGRATE | DoQ        | 0.978 |    0.960 |       0.680 | 0.796 | 0.112 |   0.019 |
| DoQ-MUX     | DoQ        | 0.957 |    0.899 |       0.662 | 0.760 | 0.112 |   0.048 |
| DoQ-VERNEG  | DoQ        | 0.992 |    0.984 |       0.695 | 0.815 | 0.112 |   0.022 |
| DoT-CERT    | DoT        | 0.984 |    0.943 |       0.734 | 0.824 | 0.092 |   0.044 |
| DoT-RENEG   | DoT        | 0.998 |    0.995 |       0.745 | 0.851 | 0.092 |   0.042 |
| DoT-TICKET  | DoT        | 0.976 |    0.918 |       0.696 | 0.790 | 0.092 |   0.055 |
| S1-Timing   | DoH        | 0.889 |    0.771 |       0.587 | 0.660 | 0.155 |   0.068 |
| S2-Tunnel   | DoH        | 0.999 |    1.000 |       0.651 | 0.786 | 0.155 |   0.061 |
| S2-Tunnel   | DoQ        | 0.999 |    1.000 |       0.697 | 0.820 | 0.112 |   0.051 |
| S2-Tunnel   | DoT        | 1.000 |    1.000 |       0.725 | 0.838 | 0.092 |   0.060 |
| S4-Quantum  | DoH        | 0.997 |    1.000 |       0.621 | 0.764 | 0.155 |   0.052 |
| S5-Evasion  | DoH        | 0.884 |    0.780 |       0.564 | 0.650 | 0.155 |   0.105 |
| S5-Evasion  | DoQ        | 0.904 |    0.760 |       0.628 | 0.687 | 0.112 |   0.068 |
| S5-Evasion  | DoT        | 0.911 |    0.738 |       0.670 | 0.700 | 0.092 |   0.064 |

Severity sweep (detector trained at severity 1.0):

|   severity |    f1 |   recall |   fpr |   acc |
|-----------:|------:|---------:|------:|------:|
|      0.250 | 0.412 |    0.283 | 0.129 | 0.526 |
|      0.500 | 0.665 |    0.544 | 0.129 | 0.679 |
|      0.750 | 0.827 |    0.769 | 0.129 | 0.811 |
|      1.000 | 0.905 |    0.902 | 0.129 | 0.889 |
|      1.500 | 0.951 |    0.989 | 0.129 | 0.940 |

Recall falls from 0.90 at severity 1.0 to 0.28 at severity 0.25, so a detector trained on full-strength attacks misses weak ones. The benign false-positive rate is the same in every row because the benign sample is the same.

## 9.2 Adversarial robustness (E9)

L-infinity PGD in standardised feature units. At epsilon = 0.3 (the value of Table 30) the standard detector has accuracy 0.492 and the PGD-trained detector 0.721; on clean data the standard detector has accuracy 0.892 and the PGD-trained one 0.857. Adversarial training buys robustness at a cost in clean accuracy and false positives.

| model       |   pgd_eps |   acc |    f1 |   fpr |
|:------------|----------:|------:|------:|------:|
| pgd_trained |     0.000 | 0.857 | 0.867 | 0.051 |
| pgd_trained |     0.100 | 0.818 | 0.829 | 0.090 |
| pgd_trained |     0.200 | 0.775 | 0.789 | 0.140 |
| pgd_trained |     0.300 | 0.721 | 0.740 | 0.209 |
| pgd_trained |     0.500 | 0.590 | 0.625 | 0.395 |
| standard    |     0.000 | 0.892 | 0.908 | 0.119 |
| standard    |     0.100 | 0.785 | 0.817 | 0.261 |
| standard    |     0.200 | 0.640 | 0.702 | 0.476 |
| standard    |     0.300 | 0.492 | 0.586 | 0.675 |
| standard    |     0.500 | 0.278 | 0.404 | 0.919 |

Blending attack (the attacker moves tunnel statistics toward benign by a factor; 1.0 is unmodified):

| model       |   blend |   detection_rate |
|:------------|--------:|-----------------:|
| pgd_trained |   0.200 |            0.176 |
| pgd_trained |   0.400 |            0.644 |
| pgd_trained |   0.600 |            0.966 |
| pgd_trained |   0.800 |            0.997 |
| pgd_trained |   1.000 |            1.000 |
| standard    |   0.200 |            0.272 |
| standard    |   0.400 |            0.698 |
| standard    |   0.600 |            0.970 |
| standard    |   0.800 |            0.997 |
| standard    |   1.000 |            1.000 |

Blending to 40 % of the tunnel shift drops detection of the DoH tunnel to 0.70 for the standard detector; the PGD-trained detector is not better against this attack (0.64), because blending moves along the benign direction and not along the gradient.

## 9.3 Byzantine aggregation (E2)

K = 50 clients, 40 rounds, three seeds, update clipping at 2.0 for every aggregator. Under 40 % gradient-flipping clients the F1 is 0.584 for the plain mean, 0.829 for the coordinate median, 0.833 for the geometric median and 0.880 for the MAD filter followed by the geometric median. The MAD filter keeps the F1 at the level of the attack-free run (0.883).

![Byzantine sweep](../../results_v2/figures/e2_byzantine_sweep.png)

Two caveats. The `backdoor_scale` attack multiplies an honest update by 10; after clipping it only changes the step size and not its direction, so it is not harmful here and is not a real backdoor. A trigger-based backdoor needs its own experiment. The MAD filter also assumes that malicious updates are far from the median; the adaptive attack that stays under the cut-off is listed as open question Q5.

| attack         |   byz_frac | method     |    f1 |   f1_sd |   fpr |   acc |
|:---------------|-----------:|:-----------|------:|--------:|------:|------:|
| backdoor_scale |      0.000 | geomed     | 0.883 |   0.021 | 0.158 | 0.866 |
| backdoor_scale |      0.000 | mad_geomed | 0.883 |   0.021 | 0.158 | 0.866 |
| backdoor_scale |      0.000 | mean       | 0.887 |   0.021 | 0.157 | 0.871 |
| backdoor_scale |      0.000 | median     | 0.880 |   0.022 | 0.155 | 0.863 |
| backdoor_scale |      0.200 | geomed     | 0.889 |   0.018 | 0.152 | 0.873 |
| backdoor_scale |      0.200 | mad_geomed | 0.881 |   0.020 | 0.161 | 0.863 |
| backdoor_scale |      0.200 | mean       | 0.897 |   0.018 | 0.127 | 0.883 |
| backdoor_scale |      0.200 | median     | 0.886 |   0.020 | 0.153 | 0.869 |
| backdoor_scale |      0.400 | geomed     | 0.892 |   0.018 | 0.145 | 0.877 |
| backdoor_scale |      0.400 | mad_geomed | 0.880 |   0.022 | 0.165 | 0.863 |
| backdoor_scale |      0.400 | mean       | 0.898 |   0.013 | 0.125 | 0.884 |
| backdoor_scale |      0.400 | median     | 0.889 |   0.018 | 0.150 | 0.873 |
| gradient_flip  |      0.000 | geomed     | 0.883 |   0.021 | 0.158 | 0.866 |
| gradient_flip  |      0.000 | mad_geomed | 0.883 |   0.021 | 0.158 | 0.866 |
| gradient_flip  |      0.000 | mean       | 0.887 |   0.021 | 0.157 | 0.871 |
| gradient_flip  |      0.000 | median     | 0.880 |   0.022 | 0.155 | 0.863 |
| gradient_flip  |      0.200 | geomed     | 0.871 |   0.017 | 0.180 | 0.852 |
| gradient_flip  |      0.200 | mad_geomed | 0.881 |   0.020 | 0.161 | 0.863 |
| gradient_flip  |      0.200 | mean       | 0.810 |   0.008 | 0.290 | 0.777 |
| gradient_flip  |      0.200 | median     | 0.867 |   0.021 | 0.176 | 0.848 |
| gradient_flip  |      0.400 | geomed     | 0.833 |   0.016 | 0.277 | 0.802 |
| gradient_flip  |      0.400 | mad_geomed | 0.880 |   0.022 | 0.167 | 0.862 |
| gradient_flip  |      0.400 | mean       | 0.584 |   0.091 | 0.485 | 0.543 |
| gradient_flip  |      0.400 | median     | 0.829 |   0.008 | 0.277 | 0.798 |
| label_flip     |      0.000 | geomed     | 0.883 |   0.021 | 0.158 | 0.866 |
| label_flip     |      0.000 | mad_geomed | 0.883 |   0.021 | 0.158 | 0.866 |
| label_flip     |      0.000 | mean       | 0.887 |   0.021 | 0.157 | 0.871 |
| label_flip     |      0.000 | median     | 0.880 |   0.022 | 0.155 | 0.863 |
| label_flip     |      0.200 | geomed     | 0.877 |   0.019 | 0.170 | 0.858 |
| label_flip     |      0.200 | mad_geomed | 0.881 |   0.020 | 0.161 | 0.863 |
| label_flip     |      0.200 | mean       | 0.865 |   0.019 | 0.193 | 0.844 |
| label_flip     |      0.200 | median     | 0.880 |   0.017 | 0.148 | 0.864 |
| label_flip     |      0.400 | geomed     | 0.859 |   0.016 | 0.207 | 0.837 |
| label_flip     |      0.400 | mad_geomed | 0.881 |   0.019 | 0.169 | 0.863 |
| label_flip     |      0.400 | mean       | 0.798 |   0.015 | 0.299 | 0.765 |
| label_flip     |      0.400 | median     | 0.838 |   0.006 | 0.145 | 0.823 |
| random_noise   |      0.000 | geomed     | 0.883 |   0.021 | 0.158 | 0.866 |
| random_noise   |      0.000 | mad_geomed | 0.883 |   0.021 | 0.158 | 0.866 |
| random_noise   |      0.000 | mean       | 0.887 |   0.021 | 0.157 | 0.871 |
| random_noise   |      0.000 | median     | 0.880 |   0.022 | 0.155 | 0.863 |
| random_noise   |      0.200 | geomed     | 0.882 |   0.024 | 0.159 | 0.865 |
| random_noise   |      0.200 | mad_geomed | 0.883 |   0.023 | 0.159 | 0.866 |
| random_noise   |      0.200 | mean       | 0.877 |   0.024 | 0.169 | 0.859 |
| random_noise   |      0.200 | median     | 0.876 |   0.022 | 0.163 | 0.858 |
| random_noise   |      0.400 | geomed     | 0.874 |   0.023 | 0.169 | 0.856 |
| random_noise   |      0.400 | mad_geomed | 0.879 |   0.024 | 0.167 | 0.861 |
| random_noise   |      0.400 | mean       | 0.866 |   0.018 | 0.184 | 0.846 |
| random_noise   |      0.400 | median     | 0.873 |   0.018 | 0.171 | 0.855 |

## 9.4 Differential privacy (E3)

K = 100, 100 rounds, Gaussian mechanism, RDP accounting without sub-sampling amplification, delta = 1e-5.

|   eps_target |   sigma |   eps_spent |    f1 |   f1_sd |   fpr |   acc |
|-------------:|--------:|------------:|------:|--------:|------:|------:|
|      inf     |   0.000 |     inf     | 0.900 |   0.020 | 0.126 | 0.886 |
|        8.000 |   6.904 |       8.000 | 0.842 |   0.013 | 0.294 | 0.809 |
|        4.000 |  12.961 |       4.000 | 0.812 |   0.014 | 0.393 | 0.766 |
|        2.000 |  24.995 |       2.000 | 0.798 |   0.027 | 0.368 | 0.755 |
|        1.000 |  49.006 |       1.000 | 0.777 |   0.041 | 0.352 | 0.738 |
|        0.700 |  69.577 |       0.700 | 0.749 |   0.064 | 0.376 | 0.710 |
|        0.680 |  71.595 |       0.680 | 0.749 |   0.068 | 0.375 | 0.710 |

At epsilon = 0.68 the F1 is 0.749 against 0.900 without noise, a drop of 0.151. Chapter 6 reports about 0.4 percentage points. The gap most likely comes from the missing sampling amplification and from the small detector; we list it as open question Q2 and do not treat it as a refutation. The noise multiplier needed for each (epsilon, rounds) pair is in `results_v2/tables/e3_dp_calibration_grid.csv`.

![DP accountant](../../results_v2/figures/e3_dp_accountant.png)

## 9.5 Homomorphic layer (E4)

Toy parameters. Plaintext modulus is 2 for the two sets named after the thesis tables and 256 for the NTT-friendly set, so their noise budgets are not directly comparable.

- **Noise budget (E4a).** With repeated addition of fresh ciphertexts, decryption first fails after 14 summands for the Table 27 set (n = 1024, q = 3329), 76 for the Table 34a set (n = 256, q = 4096) and 252 for the NTT set (n = 256, q = 786433). The encrypted-histogram aggregation of Section 6.5.3 therefore needs a stated bound on the number of reporters.
- **Samplers (E4b).** Both samplers match the target distribution (chi-square p = 0.78 and 0.77); the table-driven one is 3.8x faster than rejection sampling in this NumPy setting.
- **Encrypted histograms (E4e).** 10 reporters x 25 queries per aggregate. The decrypted aggregate equals the plaintext histogram in 100 % of trials. The chi-square test separates benign from tunnel-like windows with AUC 1.00; an adversary that sees only ciphertext coefficients reaches AUC 0.49, which is chance.
- **Selective operations (E4f).** Processing 2 of 16 features gives an 8x reduction in encrypted values and F1 0.789, against 0.914 for all 16. The reduction has a price in detection quality; Chapter 6 reports the factor 8 without that price.
- **Latency and size (E4d).** Single-threaded NumPy: encrypt 0.12 ms, add 0.004 ms, decrypt 0.045 ms for n = 256. These are host timings and say nothing about the 28x speedup of the optimised implementation.

![noise growth](../../results_v2/figures/e4_noise_growth.png)

| params          |    n |      q |   t |   delta |   additions_plus1 |   max_abs_noise |   half_delta |   ratio |
|:----------------|-----:|-------:|----:|--------:|------------------:|----------------:|-------------:|--------:|
| thesis_table34a |  256 |   4096 |   2 |    2048 |                 1 |         81.0000 |         1024 |  0.0791 |
| thesis_table34a |  256 |   4096 |   2 |    2048 |                 2 |        132.0000 |         1024 |  0.1289 |
| thesis_table34a |  256 |   4096 |   2 |    2048 |                 4 |        194.0000 |         1024 |  0.1895 |
| thesis_table34a |  256 |   4096 |   2 |    2048 |                 8 |        217.0000 |         1024 |  0.2119 |
| thesis_table34a |  256 |   4096 |   2 |    2048 |                16 |        362.0000 |         1024 |  0.3535 |
| thesis_table34a |  256 |   4096 |   2 |    2048 |                32 |        531.0000 |         1024 |  0.5186 |
| thesis_table34a |  256 |   4096 |   2 |    2048 |                64 |        874.0000 |         1024 |  0.8535 |
| thesis_table34a |  256 |   4096 |   2 |    2048 |                76 |                 |         1024 |         |
| thesis_table27  | 1024 |   3329 |   2 |    1664 |                 1 |        169.0000 |          832 |  0.2031 |
| thesis_table27  | 1024 |   3329 |   2 |    1664 |                 2 |        267.0000 |          832 |  0.3209 |
| thesis_table27  | 1024 |   3329 |   2 |    1664 |                 4 |        322.0000 |          832 |  0.3870 |
| thesis_table27  | 1024 |   3329 |   2 |    1664 |                 8 |        550.0000 |          832 |  0.6611 |
| thesis_table27  | 1024 |   3329 |   2 |    1664 |                14 |                 |          832 |         |
| ntt_n256        |  256 | 786433 | 256 |    3072 |                 1 |         81.0000 |         1536 |  0.0527 |
| ntt_n256        |  256 | 786433 | 256 |    3072 |                 2 |        132.0000 |         1536 |  0.0859 |
| ntt_n256        |  256 | 786433 | 256 |    3072 |                 4 |        193.0000 |         1536 |  0.1257 |
| ntt_n256        |  256 | 786433 | 256 |    3072 |                 8 |        221.0000 |         1536 |  0.1439 |
| ntt_n256        |  256 | 786433 | 256 |    3072 |                16 |        355.0000 |         1536 |  0.2311 |
| ntt_n256        |  256 | 786433 | 256 |    3072 |                32 |        546.0000 |         1536 |  0.3555 |
| ntt_n256        |  256 | 786433 | 256 |    3072 |                64 |        903.0000 |         1536 |  0.5879 |
| ntt_n256        |  256 | 786433 | 256 |    3072 |               128 |       1141.0000 |         1536 |  0.7428 |
| ntt_n256        |  256 | 786433 | 256 |    3072 |               252 |                 |         1536 |         |

## 9.6 Adaptive evolutionary encryption (E5)

- **SE(3) update (E5a).** The closed-form exponential agrees with `scipy.linalg.expm` to 1.15e-13 over 2000 random twists, and every result is a rigid transform.
- **Key stream screening (E5b).** 3000 keys, 3000 unique; mean Hamming distance between consecutive keys 128.0 of 256 (ideal 128); Shannon entropy 7.9983 bits per byte; min-entropy 7.81 bits per byte; mean rotation cadence 10.4 s (range 5.0 to 15.0). This is statistical screening and not a security argument; Chapter 6 makes no IND-CCA2 claim for the schedule.
- **Controller cost (E5e).** The 2 x 64 controller has 6808 parameters. int8 weight rounding changes outputs by at most 0.009; it gives no speed-up in NumPy because the weights are rounded and not executed in integer arithmetic. The complete update (controller, SDE step, SE(3), HKDF) takes 338 microseconds median in NumPy, against the 45 microseconds of the optimised path in Chapter 6.
- **Timing side channel (E5f).** An observer who tries to tell cache hits from misses using eight inter-arrival times per window has AUC 0.78 without jitter. With mean added delay 61 ms the AUC falls to 0.59. The curve is not monotone at the smallest setting (the first nonzero point is within noise of the baseline). Protection from timing jitter has a latency price that grows linearly, which is the trade-off Q4 asks the testbed to measure.

![side channel](../../results_v2/figures/e5_side_channel_tradeoff.png)

![key stream](../../results_v2/figures/e5_key_stream.png)

## 9.7 Ablation (E6)

| config           |   AEE |   QHE |   FL |   f1_clean |   f1_20pct_byz |   timing_adversary_auc |   analyzer_view_auc |   added_delay_ms |
|:-----------------|------:|------:|-----:|-----------:|---------------:|-----------------------:|--------------------:|-----------------:|
| AEE=0 QHE=0 FL=0 |     0 |     0 |    0 |      0.819 |          0.819 |                  0.781 |               0.960 |            0.000 |
| AEE=0 QHE=0 FL=1 |     0 |     0 |    1 |      0.885 |          0.884 |                  0.781 |               0.960 |            0.000 |
| AEE=0 QHE=1 FL=0 |     0 |     1 |    0 |      0.819 |          0.819 |                  0.781 |               0.486 |            0.160 |
| AEE=0 QHE=1 FL=1 |     0 |     1 |    1 |      0.885 |          0.884 |                  0.781 |               0.486 |            0.160 |
| AEE=1 QHE=0 FL=0 |     1 |     0 |    0 |      0.819 |          0.819 |                  0.726 |               0.960 |           15.697 |
| AEE=1 QHE=0 FL=1 |     1 |     0 |    1 |      0.885 |          0.884 |                  0.726 |               0.960 |           15.697 |
| AEE=1 QHE=1 FL=0 |     1 |     1 |    0 |      0.819 |          0.819 |                  0.726 |               0.486 |           15.857 |
| AEE=1 QHE=1 FL=1 |     1 |     1 |    1 |      0.885 |          0.884 |                  0.726 |               0.486 |           15.857 |

Robust federated training improves F1 under 20 % malicious clients from 0.819 (local-only) to 0.884. The timing adversary's AUC falls with AEE jitter and the analyzer's view falls to chance with QHE. The added delay is dominated by the jitter. In this harness the three components act on separate quantities, so interaction terms are zero by construction; whether integration produces more than the sum is the question the testbed ablation of `06_evaluation_protocol.md` must answer.

![ablation](../../results_v2/figures/e6_factorial_ablation.png)

## 9.8 Sandbox policy (E7)

| policy           |   mean_discounted_cost |   p_contained_within_40 |
|:-----------------|-----------------------:|------------------------:|
| optimal          |                  0.620 |                   0.999 |
| always_allow     |                 30.077 |                   0.987 |
| always_terminate |                  1.000 |                   1.000 |
| monitor_only     |                 38.589 |                   0.926 |

The optimal policy from value iteration has lower expected cost than always allowing or only monitoring, and lower than always terminating. Which action is optimal in the suspicious state depends on the escalation probability and the cost of staying isolated (`e7_policy_sensitivity.csv`): with a low escalation probability the policy allows, with a moderate isolation cost it isolates, and with a high isolation cost it terminates. This is a property of our small MDP.

## 9.9 Threat intelligence (E8)

At threshold 0.5 the fused noisy-OR score reaches recall 0.80 at precision 0.95; the best single source reaches recall 0.53. Fusion helps because the feeds cover different parts of the malicious set. Parsing and fusing 1,000 indicators takes 2.5 ms, inside the 100 ms bound of Section 6.7.1; 100,000 indicators take 0.79 s.

![intel](../../results_v2/figures/e8_intel.png)

## 9.10 Attack-case matrix (E10)

Recall at a 5 % benign false-positive operating point. Averaged over all cases: 0.81 for the baseline variant, 0.37 for low-and-slow and 0.41 for adaptive blending.

![case matrix](../../results_v2/figures/e10_attack_case_matrix.png)

| scenario    | protocol   |   adaptive_blend |   baseline |   low_and_slow |
|:------------|:-----------|-----------------:|-----------:|---------------:|
| DoH-HDR     | DoH        |            0.208 |      0.736 |          0.262 |
| DoH-MUX     | DoH        |            0.112 |      0.635 |          0.183 |
| DoH-RESUME  | DoH        |            0.133 |      0.604 |          0.181 |
| DoQ-MIGRATE | DoQ        |            0.373 |      0.911 |          0.380 |
| DoQ-MUX     | DoQ        |            0.354 |      0.836 |          0.328 |
| DoQ-VERNEG  | DoQ        |            0.525 |      0.951 |          0.473 |
| DoT-CERT    | DoT        |            0.401 |      0.917 |          0.348 |
| DoT-RENEG   | DoT        |            0.729 |      0.993 |          0.526 |
| DoT-TICKET  | DoT        |            0.401 |      0.870 |          0.346 |
| S1-Timing   | DoH        |            0.116 |      0.567 |          0.186 |
| S2-Tunnel   | DoH        |            0.803 |      0.995 |          0.628 |
| S2-Tunnel   | DoQ        |            0.912 |      0.999 |          0.742 |
| S2-Tunnel   | DoT        |            0.884 |      0.998 |          0.676 |
| S4-Quantum  | DoH        |            0.572 |      0.963 |          0.469 |
| S5-Evasion  | DoH        |            0.084 |      0.503 |          0.179 |
| S5-Evasion  | DoQ        |            0.193 |      0.656 |          0.246 |
| S5-Evasion  | DoT        |            0.163 |      0.575 |          0.191 |

Every scenario loses recall when the attacker weakens or blends the attack. The scenarios that lose most are those that were already weakest at baseline (S1-Timing, S5-Evasion, DoH multiplexing). S2-Tunnel keeps recall above 0.6 in both weakened variants on all three protocols.

## 9.11 What these results do and do not support

Supported by the harness: robust aggregation resists a minority of sign-flipping clients; adversarial training trades clean accuracy for robustness; ciphertext-only observers learn nothing useful from the encrypted histograms while an authorised party decrypts exact counts; timing jitter lowers an observer's accuracy at a measurable latency cost; fusing feeds raises recall.

Not supported or not tested: any absolute accuracy, latency or throughput of Chapter 6; the cost of epsilon = 0.68 on the real detector; whether the three components together outperform their separate effects; security of the lattice parameters.
