# 04. Attack scenario catalogue

This catalogue extends Tables 30 to 32 of Chapter 6 with a feature-level definition for every scenario, the signal the detector is expected to use, the response action, and three variants per scenario (baseline, low-and-slow, adaptive blend). The shifts are expressed in units of the benign feature scale of `src/a3e_dns_v2/traffic.py` and are our modelling choices for the synthetic harness. They are not measurements of the live tools named in Table 32.

**Scope.** Every scenario below is run at feature level inside the harness. Live attack tools (dnscat2, iodine and the others in Table 32) must only be run on an isolated lab network that the operator owns or is authorised to test. No tool launcher is shipped in this package.

## A. Scenario definitions

| id | protocol | family | mechanism | feature shifts at severity 1 | expected detector signal | response action | Chapter 6 reference |
|---|---|---|---|---|---|---|---|
| S1-Timing | DoH | traffic_analysis | inter-arrival distribution drifts right-skewed under timing inference | iat_mean_ms +1.6; iat_skew +2.4; iat_std_ms +0.8 | KL divergence of inter-arrival histogram against the baseline exceeds 0.3 | aee-morph timing adjustment; raise sigma | Table 32 S1; Table 30 row 1 |
| S2-Tunnel | ALL | tunneling | high-entropy, long, mostly unique labels at a steady low rate | qname_entropy_bits +3.2; subdomain_len_mean +3.4; unique_name_ratio +3.0; pkt_size_std -1.0; query_rate_per_s +1.2 | qname entropy, label length and unique-name ratio rise together at a steady low rate | quarantine flow, QHE statistical test on aggregate histogram | Table 32 S2; Table 31 'Encrypted Tunnel' |
| S4-Quantum | DoH | protocol_exploit | handshake with non-negotiated or malformed PQ key-exchange parameters | handshake_ms +2.2; proto_anomaly_score +4.0 | handshake time and protocol anomaly score rise; negotiated groups differ from policy | protocol-bind with minimum PQ-hybrid group, reject downgrade | Table 32 S4; Table 30 'QUIC Version Downgrade' |
| S5-Evasion | ALL | ml_evasion | tunnel traffic perturbed toward benign statistics | qname_entropy_bits +1.5; subdomain_len_mean +1.4; unique_name_ratio +1.4; pkt_size_std -0.4 | classifier confidence drops while qname statistics remain slightly elevated | federated adversarial training, attention window re-weighting | Table 32 S5; Table 30 'Adversarial Query Crafting' |
| DoH-MUX | DoH | stream_multiplexing | malicious queries hidden in one HTTP/2 stream among legitimate ones | stream_count +3.0; payload_entropy_bits +1.4; pkt_size_std +1.2 | stream count and payload entropy rise inside one HTTP/2 connection | RST_STREAM on the offending stream, per-stream rate limit | Section 6.15.2 |
| DoH-HDR | DoH | header_manipulation | altered request headers and metadata | proto_anomaly_score +3.0; pkt_size_mean +1.0; payload_entropy_bits +0.8 | header-derived anomaly score and request size change | drop request, log header fingerprint | Section 6.15.2 |
| DoH-RESUME | DoH | session_reuse | long-lived resumed connection masking sustained malicious activity | session_reuse_ratio +2.6; iat_std_ms -0.7; query_rate_per_s +1.6 | session reuse ratio rises, timing variance collapses, rate is sustained | force full handshake, cap ticket lifetime | Section 6.15.2 |
| DoT-RENEG | DoT | handshake_abuse | malformed handshake messages during renegotiation | handshake_ms +3.0; proto_anomaly_score +4.5; session_reuse_ratio -1.2 | handshake duration and anomaly score rise, resumption ratio falls | TLS session quarantine | Section 6.15.3 |
| DoT-CERT | DoT | certificate_abuse | inconsistent certificate chain during negotiation | handshake_ms +1.8; proto_anomaly_score +3.5 | handshake duration rises, certificate-chain checks flag inconsistency | close_notify then reset, pin chain | Section 6.15.3 |
| DoT-TICKET | DoT | session_ticket_abuse | altered session-ticket parameters | session_reuse_ratio +3.0; proto_anomaly_score +2.4; handshake_ms -0.8 | session reuse ratio far above baseline, ticket parameters inconsistent | invalidate tickets for the source | Section 6.15.3 |
| DoQ-MIGRATE | DoQ | connection_migration | modified connection IDs and changing client addresses | session_reuse_ratio -1.6; handshake_ms +1.5; proto_anomaly_score +3.2; stream_count +1.0 | connection ID changes with new client address, handshake restarts | QUIC connection pinning, validate path | Section 6.15.4 |
| DoQ-MUX | DoQ | stream_multiplexing | payload split over many concurrent streams | stream_count +3.5; payload_entropy_bits +1.2; query_rate_per_s +1.4 | concurrent stream count and payload entropy rise | stream-level reset, CONNECTION_CLOSE on repetition | Section 6.15.4 |
| DoQ-VERNEG | DoQ | version_negotiation | version negotiation steered to legacy parameters | proto_anomaly_score +4.2; handshake_ms +2.0 | anomaly score rises at version negotiation, legacy version requested | reject below minimum version | Section 6.15.4 |

## B. Case list (scenario x protocol x variant)

| case id | variant | description | parameters | metric | result location |
|---|---|---|---|---|---|
| S1-Timing/DoH/1 | baseline | full-strength attack | severity 1.0, blend 1.0 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| S1-Timing/DoH/2 | low_and_slow | half-strength attack that tries to stay under thresholds | severity 0.5, blend 1.0 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| S1-Timing/DoH/3 | adaptive_blend | attacker blends its statistics 40 % toward benign | severity 1.0, blend 0.6 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| S2-Tunnel/DoH/1 | baseline | full-strength attack | severity 1.0, blend 1.0 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| S2-Tunnel/DoH/2 | low_and_slow | half-strength attack that tries to stay under thresholds | severity 0.5, blend 1.0 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| S2-Tunnel/DoH/3 | adaptive_blend | attacker blends its statistics 40 % toward benign | severity 1.0, blend 0.6 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| S2-Tunnel/DoT/1 | baseline | full-strength attack | severity 1.0, blend 1.0 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| S2-Tunnel/DoT/2 | low_and_slow | half-strength attack that tries to stay under thresholds | severity 0.5, blend 1.0 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| S2-Tunnel/DoT/3 | adaptive_blend | attacker blends its statistics 40 % toward benign | severity 1.0, blend 0.6 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| S2-Tunnel/DoQ/1 | baseline | full-strength attack | severity 1.0, blend 1.0 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| S2-Tunnel/DoQ/2 | low_and_slow | half-strength attack that tries to stay under thresholds | severity 0.5, blend 1.0 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| S2-Tunnel/DoQ/3 | adaptive_blend | attacker blends its statistics 40 % toward benign | severity 1.0, blend 0.6 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| S4-Quantum/DoH/1 | baseline | full-strength attack | severity 1.0, blend 1.0 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| S4-Quantum/DoH/2 | low_and_slow | half-strength attack that tries to stay under thresholds | severity 0.5, blend 1.0 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| S4-Quantum/DoH/3 | adaptive_blend | attacker blends its statistics 40 % toward benign | severity 1.0, blend 0.6 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| S5-Evasion/DoH/1 | baseline | full-strength attack | severity 1.0, blend 1.0 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| S5-Evasion/DoH/2 | low_and_slow | half-strength attack that tries to stay under thresholds | severity 0.5, blend 1.0 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| S5-Evasion/DoH/3 | adaptive_blend | attacker blends its statistics 40 % toward benign | severity 1.0, blend 0.6 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| S5-Evasion/DoT/1 | baseline | full-strength attack | severity 1.0, blend 1.0 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| S5-Evasion/DoT/2 | low_and_slow | half-strength attack that tries to stay under thresholds | severity 0.5, blend 1.0 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| S5-Evasion/DoT/3 | adaptive_blend | attacker blends its statistics 40 % toward benign | severity 1.0, blend 0.6 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| S5-Evasion/DoQ/1 | baseline | full-strength attack | severity 1.0, blend 1.0 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| S5-Evasion/DoQ/2 | low_and_slow | half-strength attack that tries to stay under thresholds | severity 0.5, blend 1.0 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| S5-Evasion/DoQ/3 | adaptive_blend | attacker blends its statistics 40 % toward benign | severity 1.0, blend 0.6 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| DoH-MUX/DoH/1 | baseline | full-strength attack | severity 1.0, blend 1.0 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| DoH-MUX/DoH/2 | low_and_slow | half-strength attack that tries to stay under thresholds | severity 0.5, blend 1.0 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| DoH-MUX/DoH/3 | adaptive_blend | attacker blends its statistics 40 % toward benign | severity 1.0, blend 0.6 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| DoH-HDR/DoH/1 | baseline | full-strength attack | severity 1.0, blend 1.0 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| DoH-HDR/DoH/2 | low_and_slow | half-strength attack that tries to stay under thresholds | severity 0.5, blend 1.0 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| DoH-HDR/DoH/3 | adaptive_blend | attacker blends its statistics 40 % toward benign | severity 1.0, blend 0.6 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| DoH-RESUME/DoH/1 | baseline | full-strength attack | severity 1.0, blend 1.0 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| DoH-RESUME/DoH/2 | low_and_slow | half-strength attack that tries to stay under thresholds | severity 0.5, blend 1.0 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| DoH-RESUME/DoH/3 | adaptive_blend | attacker blends its statistics 40 % toward benign | severity 1.0, blend 0.6 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| DoT-RENEG/DoT/1 | baseline | full-strength attack | severity 1.0, blend 1.0 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| DoT-RENEG/DoT/2 | low_and_slow | half-strength attack that tries to stay under thresholds | severity 0.5, blend 1.0 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| DoT-RENEG/DoT/3 | adaptive_blend | attacker blends its statistics 40 % toward benign | severity 1.0, blend 0.6 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| DoT-CERT/DoT/1 | baseline | full-strength attack | severity 1.0, blend 1.0 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| DoT-CERT/DoT/2 | low_and_slow | half-strength attack that tries to stay under thresholds | severity 0.5, blend 1.0 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| DoT-CERT/DoT/3 | adaptive_blend | attacker blends its statistics 40 % toward benign | severity 1.0, blend 0.6 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| DoT-TICKET/DoT/1 | baseline | full-strength attack | severity 1.0, blend 1.0 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| DoT-TICKET/DoT/2 | low_and_slow | half-strength attack that tries to stay under thresholds | severity 0.5, blend 1.0 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| DoT-TICKET/DoT/3 | adaptive_blend | attacker blends its statistics 40 % toward benign | severity 1.0, blend 0.6 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| DoQ-MIGRATE/DoQ/1 | baseline | full-strength attack | severity 1.0, blend 1.0 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| DoQ-MIGRATE/DoQ/2 | low_and_slow | half-strength attack that tries to stay under thresholds | severity 0.5, blend 1.0 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| DoQ-MIGRATE/DoQ/3 | adaptive_blend | attacker blends its statistics 40 % toward benign | severity 1.0, blend 0.6 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| DoQ-MUX/DoQ/1 | baseline | full-strength attack | severity 1.0, blend 1.0 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| DoQ-MUX/DoQ/2 | low_and_slow | half-strength attack that tries to stay under thresholds | severity 0.5, blend 1.0 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| DoQ-MUX/DoQ/3 | adaptive_blend | attacker blends its statistics 40 % toward benign | severity 1.0, blend 0.6 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| DoQ-VERNEG/DoQ/1 | baseline | full-strength attack | severity 1.0, blend 1.0 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| DoQ-VERNEG/DoQ/2 | low_and_slow | half-strength attack that tries to stay under thresholds | severity 0.5, blend 1.0 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |
| DoQ-VERNEG/DoQ/3 | adaptive_blend | attacker blends its statistics 40 % toward benign | severity 1.0, blend 0.6 | recall at 5 % benign FPR | reported per case in results_v2/tables/e10_attack_case_matrix.csv |

51 cases. Run them with `python experiments_v2/e10_case_matrix.py`.

## C. Chapter 6 command-level catalogue (reference copy)

The three tables below restate what Chapter 6 reports, so that every scenario in the harness can be located in the thesis.

### C.1 Table 32 (scenario simulation matrix)

| ID | tool (thesis) | pattern | detection threshold | response time | outcome | FNR |
|---|---|---|---|---|---|---|
| S1-Timing | tshark + custom | right-skewed inter-arrival distribution | D_KL(P//Q) > 0.3 | 0.4 ms | Blocked 98.7 % | 1.3 % |
| S2-Tunnel | dnscat2 | 60 B packets at 20 queries/min | H(X) < 4.2 bits | 1.2 ms | Detected 99.2 % | 0.8 % |
| S3-Poison | fl-attack | biased updates delta ~ N(0.25, 0.1), 7 malicious updates | weight deviation > 2 sigma | 2.5 ms | Mitigated 96.5 % | 3.5 % |
| S4-Quantum | liboqs | PQ-TLS handshake with lattice key exchange | quantum safety score > 0.9 | 1.8 ms | Protected 100 % | 0.0 % |
| S5-Evasion | ART | GAN-generated queries, epsilon 0.15 | confidence drop > 20 % | 0.9 ms | Detected 97.8 % | 2.2 % |

### C.2 Table 31 (injection phases)

| phase | network behaviour (thesis) | detection (thesis) | mitigation (thesis) |
|---|---|---|---|
| Reconnaissance | about 45 queries/s | federated model, p = 0.82 | rate-limit 10/s per source |
| Traffic morphing | DoH sizes ~ N(900 B, 150 B) | AEE dynamic thresholding | aee-rekey on anomaly |
| Encrypted tunnel | 60 B packets at fixed 100 ms | QHE chi-square 45.6 > critical (alpha 0.01) | quarantine flow 5 min |
| Timing attack | response-time shift over 1000 samples | DP noise t' = t + N(0, 0.5) | dp-enhance sigma 0.5 |
| Model poisoning | bias delta = 0.15, 5 clients | MAD > 2.5 sigma | median filter, trim 0.1 |
| QUIC exploit | version mismatch in negotiation | strict version binding | rollback on failure |

### C.3 Table 30 (attack vector taxonomy)

| class | attack | countermeasure (thesis) |
|---|---|---|
| Traffic analysis | statistical fingerprinting | AEE timing morph dt' = f(dt, E(t)) |
| Tunneling | DNS-over-DNS | QHE encrypted-domain pattern matching, threshold 0.87 |
| Protocol exploitation | QUIC version downgrade | strict version binding, min quic-v1 |
| ML evasion | adversarial query crafting | federated adversarial training, PGD epsilon 0.3, 50 epochs |
| Quantum preparation | harvest and decrypt | lattice KEM with periodic rotation (1 h) |
| Side channel | cache timing | noise injection t' = t + Lap(0.1/epsilon), epsilon 0.7 |
