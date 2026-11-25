# 06. Evaluation protocol for the testbed runs

This protocol turns the open points of Section 6.17 into a fixed plan. It applies to the testbed of Section 6.11; the same structure is executed on synthetic data by `experiments_v2/`.

## 6.1 Data and splits

1. Dataset: Gen-C-DDD-2022 (32 GB and above), preprocessed with `deployment/v2/scripts/dask_preprocess_v2.py`; column names go in `configs/v2/dataset_columns_v2.yaml`.
2. Split: 60 / 20 / 20 stratified by protocol and label, drawn with a fixed seed. The script writes `split_manifest.json` with per-class counts; Chapter 6 refers to those counts in the artifact.
3. Per-class count table (fill from the manifest):

| protocol | label | train | validation | test |
|---|---|---|---|---|
| DoH | benign | | | |
| DoH | attack | | | |
| DoT | benign | | | |
| DoT | attack | | | |
| DoQ | benign | | | |
| DoQ | attack | | | |

4. Leakage control: windows from one capture session never straddle splits; normalisation statistics come from the training split only.

## 6.2 Runs and seeds

Ten seeds {11, 23, 37, 41, 59, 61, 73, 89, 97, 101} for every configuration. The harness uses the first five. Seeds control data order, client partition, initialisation and noise.

## 6.3 Factorial ablation (answers Q1)

Eight configurations: every combination of AEE, QHE and FL on or off.

| config | AEE | QHE | FL | notes |
|---|---|---|---|---|
| C0 | off | off | off | static cryptography, local detector, plaintext analysis |
| C1 | off | off | on | robust federated detector |
| C2 | off | on | off | encrypted analytics only |
| C3 | off | on | on | |
| C4 | on | off | off | adaptive encryption only |
| C5 | on | off | on | |
| C6 | on | on | off | |
| C7 | on | on | on | full A3E-DNS |

Measured per configuration: detection F1 and CDS (Eq. 131), FPR, P50/P99 latency, throughput, adversary AUC for the timing observer, analyzer-view AUC, and epsilon. Effects are estimated with a linear model that includes all two-way and the three-way interaction; the three-way term is the evidence for or against the integration claim.

## 6.4 Statistics

- Confidence intervals: bootstrap with 2,000 resamples over seeds (`metrics.bootstrap_ci`).
- Pairwise tests: Welch t-test on per-seed values, McNemar on paired test-set errors, Cohen's d for effect size.
- Multiple comparisons: Holm-Bonferroni (`metrics.holm`) across the seven planned contrasts (C7 against each other configuration).
- Required seeds per group (two-sample, normal approximation):

| Cohen's d | alpha .05, power .80 | alpha .05, power .90 | alpha .05/7, power .80 | alpha .05/7, power .90 |
|---|---|---|---|---|
| 0.2 | 394 | 527 | 625 | 790 |
| 0.5 | 64 | 86 | 101 | 128 |
| 0.8 | 26 | 34 | 40 | 51 |
| 1.0 | 17 | 23 | 26 | 33 |
| 1.87 | 6 | 8 | 9 | 11 |

  Chapter 6 reports d = 1.87 for the FPR comparison; five seeds give adequate power for effects of that size but not for d below 0.8, which is why the testbed plan uses ten.

## 6.5 Privacy sweep (answers Q2)

Run epsilon in {0.3, 0.68, 0.7, 1, 2, 4, 8} with delta = 1e-5 for 100 rounds and 100 clients. Report, for each, the noise multiplier, the accountant used (RDP with and without Poisson sub-sampling), the F1 and FPR change from the no-noise run, and the per-round bandwidth (Table 27 gives 1.2 MB). `e3_dp_calibration_grid.csv` lists the noise multipliers required without amplification.

## 6.6 Byzantine sweep (answers Q5)

Malicious share {0, 10, 20, 30, 40, 45} %, attacks: gradient flip, label flip, random noise, scaled update, free rider, and one adaptive attack that keeps its distance to the median just under the MAD cut. Aggregators: mean, coordinate median, trimmed mean, geometric median, MAD plus geometric median.

## 6.7 Latency and throughput

1. Closed-loop and open-loop load generators; report open-loop latency to avoid coordinated omission.
2. Latency histograms at 1 microsecond resolution; report P50, P90, P99, P99.9 with bootstrap intervals over runs.
3. Throughput: increase offered load until P99 exceeds the stated bound; report the sustained rate and the three terms of Eq. (134).
4. Repeat under the four network profiles of `deployment/v2/scripts/netem_profiles_v2.sh`.

## 6.8 Baselines

DNSGuard and DeepFingerprint are reproduced and retrained on the same splits with the same tuning budget (Section 6.16.2). Record for each: search space, number of trials, best configuration, seeds.

## 6.9 Reporting checklist

- [ ] manifest of per-class counts attached
- [ ] seeds and software versions in `run_metadata.json`
- [ ] every figure has a table in `results_v2/tables/`
- [ ] negative results (configurations where A3E-DNS does not win) listed
- [ ] harness results and testbed results never share a table
