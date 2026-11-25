# 08. Consistency audit of Chapter 6

While turning Chapter 6 into executable code we compared every parameter and equation against every other place where it appears. Most values agree. The items below are the places where two statements differ, or where an equation leaves a choice open that code must settle. Each item gives the locations, what we did in the v2 code, and the sentence or table change we recommend so that the thesis and the repository say the same thing. Locations were checked against the text of Chapter 6.

## A. Values stated twice with different numbers

| # | item | statement 1 | statement 2 | what v2 does | recommended change |
|---|---|---|---|---|---|
| A1 | QHE ring parameters | Table 27: lattice dimension 1024, modulus 3329 | Table 34a: n = 256, q = 4096 | all three sets are implemented (`qhe/ring.py`) and compared in E4a | state which set the reported 28x speedup and the 12 % CPU figure refer to, or label Table 27 as the service command and Table 34a as the analysed set |
| A2 | SIMD slots | Section 6.5.1: 1,024 plaintext slots | Table 34a: n = 256 | slot count is capped by n (256) in `EncryptedHistogram` | 1,024 slots needs n >= 1,024; align the two |
| A3 | DP budget | Sections 6.6.5 and Table 33: epsilon = 0.68 | Table 27 (`--dp-epsilon 0.7`) and Table 30 (`--epsilon 0.7`) | registry keeps both; sweeps in E3 include 0.68 and 0.7 | use one value or explain that 0.7 is a command default |
| A4 | DP noise mechanism | Section 6.6.5: Gaussian DP-SGD | Table 27: Lap(0.1/0.7); Table 30: Laplace timing noise; Table 31: N(0, 0.5) | E3 uses the Gaussian mechanism with an RDP accountant; E5f models timing noise separately | state that gradient privacy is Gaussian and response-timing noise is a different mechanism with its own epsilon |
| A5 | AEE latency | Table 27: about 0.2 ms | Section 6.17.2: about 0.8 ms for the whole security layer | not a numeric conflict if scopes differ | add the word "AEE only" and "whole layer" |
| A6 | Throughput | Table 33: 22.5 M QPS | Section 6.15.1 introduction: a 30 M QPS load | none | say whether 30 M is offered load and 22.5 M is sustained throughput |
| A7 | Entropy source | Section 6.4.3: RDRAND, RDSEED and system entropy, whitened | Table 27 command: `/dev/urandom` | `EntropySource` mixes `os.urandom` through SHA3 | mention that `/dev/urandom` is seeded from the hardware sources, or change the command |
| A8 | S3 malicious updates | Table 32: 7 malicious updates | Table 31: `--clients 5` | E2 sweeps 0, 20 and 40 % | state the federation size and the share these counts represent |
| A9 | S5 epsilon | Table 32 (ART): 0.15 | Table 30 PGD defence: 0.3 | E9 sweeps 0 to 0.5 | say that 0.15 is the attack budget and 0.3 the training budget, if that is the intent |
| A10 | Adversarial robustness | Table 33: 96.5 % | Section 6.16 text: 96.5 % is the S3 mitigation rate, S5 is 97.8 % | none | define the Table 33 robustness metric in one sentence (which attack, which budget) |

## B. Equations that leave a choice open

| # | equation | open point | choice in v2 |
|---|---|---|---|
| B1 | Eq. (131) CDS | the two sample sets of D_JS(P_benign, P_detected) are not defined | P_benign: detector scores of ground-truth benign flows; P_detected: scores of flows the detector accepted as benign. `metrics.cds` returns the components so another reading can be dropped in |
| B2 | Eq. (133) learning rate | a literal product with the indicator gives eta = 0 whenever the indicator is 0 | decay accumulates only during a plateau; eta = eta_0 otherwise (`fl/schedule.py`) |
| B3 | Eq. (127)-(128) | clipping norm C and the MAD cut-off are not given as numbers | C = 2.0 in standardised units; MAD cut at 3 sigma (Table 27 mentions a 3 sigma isolation threshold; Table 31 mentions 2.5 sigma) |
| B4 | Eq. (134) | units for B_memory, C_CPU, B_network are not stated | `qps_max` requires consistent units from the caller |
| B5 | Table 32 S2 | threshold written as H(X) < 4.2 bits | the harness models tunnels as raising per-label entropy; state the direction and whether entropy is per character or per window |
| B6 | Section 6.4.4 | drift term mu(K, t) and L_quantum are described but not given in closed form | drift comes from the neural controller; L_quantum enters only through accumulated gradient energy (a scalar input) |

## C. Findings from the harness that bear on stated claims

These are not inconsistencies inside Chapter 6. They are results of the synthetic harness that the testbed runs should confirm or refute.

1. **DP cost.** Chapter 6 reports an accuracy cost of about 0.4 percentage points at epsilon = 0.68. In E3 (100 clients, 100 rounds, Gaussian mechanism, RDP accounting without sub-sampling amplification) the F1 cost is much larger. The most likely reasons are the absence of amplification by sampling in our accountant and a small model. The testbed sweep in `06_evaluation_protocol.md` (Section 6.5 there) isolates this.
2. **QHE noise budget.** With the toy parameters of Table 27 and Table 34a and plaintext modulus 2, E4a finds a limited number of ciphertext additions before decryption fails. The chapter's pipeline sums encrypted histograms; the number of summands that each parameter set supports should be stated.
3. **Interaction between components.** The harness ablation (E6) acts on separate quantities, so interactions are zero by construction. Section 6.16.1 notes that the benefit of integration was not isolated by ablation; only the testbed can answer that.
