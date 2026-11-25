# 10. Limitations of the v2 package and open questions

## 10.1 What this package does not claim

1. **No testbed measurements.** Every number under `results_v2/` comes from the synthetic harness. The harness figures are lower than those of Table 33 and are not tuned toward them.
2. **No cryptographic strength.** The RLWE code uses toy parameters. It reproduces the algebra (negacyclic products, discrete Gaussian noise, additive homomorphism, noise growth), not the security level of ML-KEM-1024 or of a production homomorphic library.
3. **No hardware acceleration.** AVX-512, CUDA on A100, and the 16-core pipeline are not reproduced. Latencies in E4d and E5e are single-threaded NumPy times on whatever host ran the script (recorded in `run_metadata.json`).
4. **Deployment files are uncompiled.** The XDP program, the P4 program, the Mininet script and the Compose file have not been built or started in the environment that produced this package.
5. **Feature-level attacks.** Scenarios shift feature distributions. They do not reproduce the byte-level behaviour of dnscat2, iodine or ART.

## 10.2 Open questions the testbed should answer

| # | question | experiment to run | harness precursor |
|---|---|---|---|
| Q1 | does integration add detection or robustness beyond the sum of its parts | 2^3 factorial ablation with at least 10 seeds, interaction terms estimated | E6 |
| Q2 | what is the accuracy cost of epsilon = 0.68 with sampling amplification | epsilon sweep {0.3, 0.68, 1, 2, 4, 8} with an amplified accountant | E3 |
| Q3 | how many encrypted summands does the chosen QHE parameter set support | noise-budget sweep on the production library | E4a |
| Q4 | how large is the privacy/latency trade-off of timing morphing | adversary AUC against added delay on real traces | E5f |
| Q5 | where does the MAD filter fail | adaptive poisoning that stays under the 2.5 to 3 sigma cut | E2 |
| Q6 | how does detection degrade with low-and-slow and blended attacks | live replay of E10 variants | E10 |
| Q7 | do all three protocols sustain the throughput model | measure the three terms of Eq. (134) | `metrics.qps_max` |

## 10.3 Planned extensions

- A signed-update mode for the federated coordinator (provenance for A4 and Sybil resistance).
- A real ziggurat sampler for the discrete Gaussian, to replace the CDT stand-in.
- An amplified RDP accountant with Poisson sub-sampling.
- Byte-level traffic generators for each scenario, run only on an isolated and authorised lab network.
