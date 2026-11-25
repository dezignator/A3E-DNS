#!/usr/bin/env python3
"""Generate the data-driven documents in docs/v2 (registry, scenario catalogue, thesis-results audit)."""
import os, sys
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "src"))
from a3e_dns_v2 import params, traffic as T
D = os.path.join(ROOT, "docs", "v2")

def md_table(head, rows):
    out = ["| " + " | ".join(head) + " |", "|" + "|".join("---" for _ in head) + "|"]
    for r in rows: out.append("| " + " | ".join(str(c).replace("|", "/") for c in r) + " |")
    return "\n".join(out)

def registry():
    rows = [(p.key, p.value, p.section, p.component, p.status, p.note) for p in params.REGISTRY]
    with open(os.path.join(D, "02_parameter_registry.md"), "w") as f:
        f.write("# 02. Parameter registry for Chapter 6\n\nEvery value below is copied from Chapter 6 together with its section or table. "
                "Rows marked `conflict` are values for which the chapter gives two different statements; they are discussed in `08_consistency_audit.md`. "
                "The same registry is available as CSV in `data/v2/parameter_registry_v2.csv` and as a Python object in `src/a3e_dns_v2/params.py`.\n\n")
        f.write(md_table(["key", "value", "source", "component", "status", "note"], rows)); f.write(f"\n\n{len(rows)} parameters, {len(params.conflicts())} with conflicting statements.\n")
    with open(os.path.join(ROOT, "data", "v2", "parameter_registry_v2.csv"), "w") as f: f.write(params.to_csv())

SIGNAL = {
 "S1-Timing": ("KL divergence of inter-arrival histogram against the baseline exceeds 0.3", "aee-morph timing adjustment; raise sigma"),
 "S2-Tunnel": ("qname entropy, label length and unique-name ratio rise together at a steady low rate", "quarantine flow, QHE statistical test on aggregate histogram"),
 "S4-Quantum": ("handshake time and protocol anomaly score rise; negotiated groups differ from policy", "protocol-bind with minimum PQ-hybrid group, reject downgrade"),
 "S5-Evasion": ("classifier confidence drops while qname statistics remain slightly elevated", "federated adversarial training, attention window re-weighting"),
 "DoH-MUX": ("stream count and payload entropy rise inside one HTTP/2 connection", "RST_STREAM on the offending stream, per-stream rate limit"),
 "DoH-HDR": ("header-derived anomaly score and request size change", "drop request, log header fingerprint"),
 "DoH-RESUME": ("session reuse ratio rises, timing variance collapses, rate is sustained", "force full handshake, cap ticket lifetime"),
 "DoT-RENEG": ("handshake duration and anomaly score rise, resumption ratio falls", "TLS session quarantine"),
 "DoT-CERT": ("handshake duration rises, certificate-chain checks flag inconsistency", "close_notify then reset, pin chain"),
 "DoT-TICKET": ("session reuse ratio far above baseline, ticket parameters inconsistent", "invalidate tickets for the source"),
 "DoQ-MIGRATE": ("connection ID changes with new client address, handshake restarts", "QUIC connection pinning, validate path"),
 "DoQ-MUX": ("concurrent stream count and payload entropy rise", "stream-level reset, CONNECTION_CLOSE on repetition"),
 "DoQ-VERNEG": ("anomaly score rises at version negotiation, legacy version requested", "reject below minimum version"),
}
THESIS_REF = {"S1-Timing": "Table 32 S1; Table 30 row 1", "S2-Tunnel": "Table 32 S2; Table 31 'Encrypted Tunnel'", "S4-Quantum": "Table 32 S4; Table 30 'QUIC Version Downgrade'",
 "S5-Evasion": "Table 32 S5; Table 30 'Adversarial Query Crafting'", "DoH-MUX": "Section 6.15.2", "DoH-HDR": "Section 6.15.2", "DoH-RESUME": "Section 6.15.2",
 "DoT-RENEG": "Section 6.15.3", "DoT-CERT": "Section 6.15.3", "DoT-TICKET": "Section 6.15.3", "DoQ-MIGRATE": "Section 6.15.4", "DoQ-MUX": "Section 6.15.4", "DoQ-VERNEG": "Section 6.15.4"}

def scenarios():
    rows = []
    for sid, sc in T.SCENARIOS.items():
        sh = "; ".join(f"{k} {'+' if v > 0 else '-'}{abs(v)}" for k, v in sc.shift.items())
        rows.append((sid, sc.protocol, sc.family, sc.description, sh, SIGNAL[sid][0], SIGNAL[sid][1], THESIS_REF[sid]))
    cases = []
    for sid, sc in T.SCENARIOS.items():
        protos = T.PROTOCOLS if sc.protocol == "ALL" else (sc.protocol,)
        for p in protos:
            for k, (vn, desc, par) in enumerate((("baseline", "full-strength attack", "severity 1.0, blend 1.0"), ("low_and_slow", "half-strength attack that tries to stay under thresholds", "severity 0.5, blend 1.0"),
                                                 ("adaptive_blend", "attacker blends its statistics 40 % toward benign", "severity 1.0, blend 0.6")), 1):
                cases.append((f"{sid}/{p}/{k}", vn, desc, par, "recall at 5 % benign FPR", "reported per case in results_v2/tables/e10_attack_case_matrix.csv"))
    with open(os.path.join(D, "04_attack_scenario_catalogue.md"), "w") as f:
        f.write("# 04. Attack scenario catalogue\n\nThis catalogue extends Tables 30 to 32 of Chapter 6 with a feature-level definition for every scenario, the signal the detector is expected to use, "
                "the response action, and three variants per scenario (baseline, low-and-slow, adaptive blend). The shifts are expressed in units of the benign feature scale of "
                "`src/a3e_dns_v2/traffic.py` and are our modelling choices for the synthetic harness. They are not measurements of the live tools named in Table 32.\n\n"
                "**Scope.** Every scenario below is run at feature level inside the harness. Live attack tools (dnscat2, iodine and the others in Table 32) must only be run on an isolated lab network that the "
                "operator owns or is authorised to test. No tool launcher is shipped in this package.\n\n## A. Scenario definitions\n\n")
        f.write(md_table(["id", "protocol", "family", "mechanism", "feature shifts at severity 1", "expected detector signal", "response action", "Chapter 6 reference"], rows))
        f.write("\n\n## B. Case list (scenario x protocol x variant)\n\n"); f.write(md_table(["case id", "variant", "description", "parameters", "metric", "result location"], cases))
        f.write(f"\n\n{len(cases)} cases. Run them with `python experiments_v2/e10_case_matrix.py`.\n\n## C. Chapter 6 command-level catalogue (reference copy)\n\n"
                "The three tables below restate what Chapter 6 reports, so that every scenario in the harness can be located in the thesis.\n\n### C.1 Table 32 (scenario simulation matrix)\n\n")
        f.write(md_table(["ID", "tool (thesis)", "pattern", "detection threshold", "response time", "outcome", "FNR"], [
          ("S1-Timing", "tshark + custom", "right-skewed inter-arrival distribution", "D_KL(P||Q) > 0.3", "0.4 ms", "Blocked 98.7 %", "1.3 %"),
          ("S2-Tunnel", "dnscat2", "60 B packets at 20 queries/min", "H(X) < 4.2 bits", "1.2 ms", "Detected 99.2 %", "0.8 %"),
          ("S3-Poison", "fl-attack", "biased updates delta ~ N(0.25, 0.1), 7 malicious updates", "weight deviation > 2 sigma", "2.5 ms", "Mitigated 96.5 %", "3.5 %"),
          ("S4-Quantum", "liboqs", "PQ-TLS handshake with lattice key exchange", "quantum safety score > 0.9", "1.8 ms", "Protected 100 %", "0.0 %"),
          ("S5-Evasion", "ART", "GAN-generated queries, epsilon 0.15", "confidence drop > 20 %", "0.9 ms", "Detected 97.8 %", "2.2 %")]))
        f.write("\n\n### C.2 Table 31 (injection phases)\n\n")
        f.write(md_table(["phase", "network behaviour (thesis)", "detection (thesis)", "mitigation (thesis)"], [
          ("Reconnaissance", "about 45 queries/s", "federated model, p = 0.82", "rate-limit 10/s per source"),
          ("Traffic morphing", "DoH sizes ~ N(900 B, 150 B)", "AEE dynamic thresholding", "aee-rekey on anomaly"),
          ("Encrypted tunnel", "60 B packets at fixed 100 ms", "QHE chi-square 45.6 > critical (alpha 0.01)", "quarantine flow 5 min"),
          ("Timing attack", "response-time shift over 1000 samples", "DP noise t' = t + N(0, 0.5)", "dp-enhance sigma 0.5"),
          ("Model poisoning", "bias delta = 0.15, 5 clients", "MAD > 2.5 sigma", "median filter, trim 0.1"),
          ("QUIC exploit", "version mismatch in negotiation", "strict version binding", "rollback on failure")]))
        f.write("\n\n### C.3 Table 30 (attack vector taxonomy)\n\n")
        f.write(md_table(["class", "attack", "countermeasure (thesis)"], [
          ("Traffic analysis", "statistical fingerprinting", "AEE timing morph dt' = f(dt, E(t))"), ("Tunneling", "DNS-over-DNS", "QHE encrypted-domain pattern matching, threshold 0.87"),
          ("Protocol exploitation", "QUIC version downgrade", "strict version binding, min quic-v1"), ("ML evasion", "adversarial query crafting", "federated adversarial training, PGD epsilon 0.3, 50 epochs"),
          ("Quantum preparation", "harvest and decrypt", "lattice KEM with periodic rotation (1 h)"), ("Side channel", "cache timing", "noise injection t' = t + Lap(0.1/epsilon), epsilon 0.7")]))
        f.write("\n")

def thesis_results():
    rows = [("Detection accuracy", 91.2, 96.7, 99.94, "pp"), ("False-positive rate (%)", 2.1, 0.8, 0.17, "ratio_low"), ("P99 latency (ms)", 4.2, 2.8, 1.42, "ratio_low"),
            ("Throughput (M QPS)", 8, 15, 22.5, "ratio_high"), ("Adversarial robustness (%)", 65, 82, 96.5, "pp")]
    out = []
    for name, a, b, p, kind in rows:
        if kind == "pp": ra, rb = f"+{p - a:.2f} pp", f"+{p - b:.2f} pp"
        elif kind == "ratio_low": ra, rb = f"{a / p:.2f}x lower", f"{b / p:.2f}x lower"
        else: ra, rb = f"{p / a:.2f}x higher", f"{p / b:.2f}x higher"
        out.append((name, a, b, p, ra, rb))
    with open(os.path.join(D, "07_thesis_reported_results.md"), "w") as f:
        f.write("# 07. Results reported in Chapter 6 and an arithmetic check\n\nThese are the thesis figures (Table 32, Table 33). They are **not produced by the v2 harness**. "
                "They come from the testbed of Section 6.11 and are reproduced here so that the repository contains one place where every reported number can be traced and recomputed.\n\n"
                "## Table 33 with recomputed improvement columns\n\n")
        f.write(md_table(["metric", "DNSGuard", "DeepFingerprint", "A3E-DNS", "recomputed vs DNSGuard", "recomputed vs DeepFingerprint"], out))
        f.write("\n\nAll recomputed values equal the improvement column printed in Table 33 (8.74 pp / 3.24 pp, 12.35x / 4.71x, 2.96x / 1.97x, 2.81x / 1.50x, 31.5 pp / 14.5 pp).\n\n"
                "Other reported quantities: P99 95 % CI [1.38, 1.46] ms; throughput efficiency 0.92; adversarial gap 0.035 (= 1 - 0.965); Cohen's d = 1.87 for the FPR comparison; "
                "t-test p < 0.0001 for accuracy; epsilon = 0.68; estimated security parameter lambda = 256 (conjectured, lattice-based).\n\n"
                "## Table 32 per scenario\n\n")
        f.write(md_table(["scenario", "response time", "success", "FNR", "success + FNR"], [("S1-Timing", "0.4 ms", "98.7 %", "1.3 %", "100.0 %"), ("S2-Tunnel", "1.2 ms", "99.2 %", "0.8 %", "100.0 %"),
                ("S3-Poison", "2.5 ms", "96.5 %", "3.5 %", "100.0 %"), ("S4-Quantum", "1.8 ms", "100 %", "0.0 %", "100.0 %"), ("S5-Evasion", "0.9 ms", "97.8 %", "2.2 %", "100.0 %")]))
        f.write("\n\nEach row is internally consistent: success and FNR add to 100 %.\n\n"
                "## How the v2 harness relates to these numbers\n\nThe harness in `experiments_v2/` runs on a synthetic generator whose attack classes overlap by design. Its absolute numbers (for example detection F1 about 0.9) are lower than the thesis values and "
                "are not tuned to match them. The harness is intended to reproduce *directions of effect* (robust aggregation under malicious clients, the privacy/utility trade-off, the noise budget of the QHE parameters, the privacy/latency trade-off of timing jitter) and to give the testbed runs an executable specification. "
                "The testbed numbers above remain the only measured values for Chapter 6.\n")

if __name__ == "__main__":
    os.makedirs(D, exist_ok=True); registry(); scenarios(); thesis_results(); print("docs built")
