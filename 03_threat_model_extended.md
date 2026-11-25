# 03. Extended threat model

Section 6.2 defines the traffic space, the adversarial operators and the Byzantine model. This document restates them as a table of adversaries, assets and assumptions, and connects each adversary to the component that addresses it, the harness experiment that exercises it, and the residual risk we still see.

## 3.1 Assets and trust boundaries

| asset | where it lives | confidentiality / integrity goal |
|---|---|---|
| DNS query content | client to resolver, inside DoH, DoT or DoQ | hidden from on-path observers |
| traffic timing and size metadata | observable on the wire | should not reveal resolver state or service identity |
| session keys and AEE state | resolver and client | forward secrecy; unpredictability of the schedule |
| client-side training data | each federated participant | never leaves the participant; bounded leakage through updates (epsilon) |
| global detection model | FL coordinator | resilient to poisoned updates |
| aggregate traffic statistics | QHE analyzer | analyzer sees ciphertext only; authorised party decrypts aggregates |
| threat-intelligence indicators | intel store | integrity and provenance of feeds |

Trust boundaries: (1) client / network, (2) network / resolver front end, (3) resolver / QHE analyzer, (4) participants / FL coordinator, (5) feed providers / intel store.

## 3.2 Adversary classes

| id | adversary | capability | goal | component that answers it | harness experiment | residual risk |
|---|---|---|---|---|---|---|
| A1 | passive on-path observer | sees sizes and timing of encrypted flows | fingerprint services, infer cache state | AEE timing adjustment | E5f | jitter costs latency; fingerprint resistance is statistical, not proven |
| A2 | active on-path attacker | alters handshake, versions, headers | downgrade, session abuse | protocol binding, sandbox actions | E10 (S4, DoT-*, DoQ-VERNEG) | detection depends on handshake features being visible |
| A3 | tunnel operator | controls both endpoints of a covert channel | exfiltrate data through DNS | QHE statistics, detector | E1, E4e, E10 (S2) | low-rate tunnels near the benign profile |
| A4 | malicious federated participant | submits arbitrary updates | poison or backdoor the model | clipping, MAD filter, geometric median | E2 | bound f < N/2; adaptive attackers who stay under the MAD cut |
| A5 | honest-but-curious analyzer | reads all ciphertexts and metadata | learn per-window content | QHE | E4e (ciphertext-only adversary) | metadata such as report counts and timing remain visible |
| A6 | harvest-now-decrypt-later | stores traffic for future quantum attacks | retrospective decryption | lattice-based KEM layer | not exercised | conjectural hardness only (Chapter 6 states this) |
| A7 | adaptive ML evader | queries the detector, crafts inputs | cross the decision boundary | PGD training, attention | E1/E9, E10 (adaptive_blend) | robustness falls as epsilon grows (E9a) |
| A8 | cache prober | measures response-time variance | learn resolver cache state | timing noise | E5f | trade-off between privacy and delay |
| A9 | poisoned intelligence feed | injects false indicators | cause false blocks | reputation-weighted fusion | E8 | a high-reputation feed that turns hostile |

## 3.3 Per-component threat analysis

| component | spoofing | tampering | repudiation | information disclosure | denial of service | elevation |
|---|---|---|---|---|---|---|
| AEE | entropy source substitution | key-schedule manipulation | no audit of rekey events | schedule leakage through timing | forced rekey storms | fail-over scheme downgrade |
| QHE | forged reports | ciphertext malleability (additive scheme) | unsigned reports | metadata of reporting | noise-budget exhaustion (E4a) | key holder compromise |
| FL | Sybil participants | poisoned updates | no signed updates | gradient leakage | stragglers, oversized updates | coordinator compromise |
| Sandbox | flow mislabelling | escape from isolation | missing action log | log contents | resource exhaustion (2 GB, 30 s limits) | container breakout |
| Intel | feed impersonation | indicator tampering | feed provenance | indicator exposure | feed flooding (E8 throughput) | rule injection |

## 3.4 Assumptions we make explicit

1. At most N/2 participants are Byzantine (Section 6.2.3). Experiments in E2 stop at 40 %.
2. The QHE parameters in the harness are toy parameters. They show structure and noise growth; they do not provide security.
3. The key-evolution schedule is heuristic. Chapter 6 states that no IND-CCA2 claim is made for it; the formal argument applies to the KEM layer.
4. Timing jitter is modelled by us as a non-negative delay with scale proportional to the diffusion level. Chapter 6 describes timing morphing in terms of a function of the entropy state; the exact mapping is our modelling choice.
5. Attack scenarios are feature-level and synthetic. Live tool behaviour must be measured on the testbed.
