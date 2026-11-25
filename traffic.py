"""Synthetic feature-level traffic generator (Sections 6.2.1, 6.3.3, 6.15).

The generator produces flow-window feature vectors, not packets. A
vector has D = 16 protocol-independent features (the common feature
space of Section 6.3.3). Attack scenarios are expressed as parameter
shifts of the benign generator; the shifts are our own modelling
choices and are listed in docs/v2/04_attack_scenario_catalogue.md.
Results computed on this generator are synthetic-simulation results.
"""
from dataclasses import dataclass
import numpy as np

FEATURES = [
 "pkt_size_mean","pkt_size_std","pkt_size_skew",
 "iat_mean_ms","iat_std_ms","iat_skew",
 "qname_entropy_bits","payload_entropy_bits","query_rate_per_s",
 "resp_to_query_ratio","subdomain_len_mean","unique_name_ratio",
 "handshake_ms","session_reuse_ratio","stream_count","proto_anomaly_score",
]
D = len(FEATURES)
PROTOCOLS = ("DoH","DoT","DoQ")

_BENIGN = {
 #            size_m size_s skew iat_m iat_s iat_k  qH   pH   qps  r2q  sub  uniq hs   reuse streams anom
 "DoH": [  150.0, 40.0, 0.6, 35.0, 30.0, 1.4, 3.1, 7.2,  9.0, 1.00, 11.0, 0.55, 42.0, 0.70, 4.0, 0.05],
 "DoT": [  128.0, 30.0, 0.5, 40.0, 33.0, 1.3, 3.0, 7.3,  7.0, 1.00, 10.5, 0.50, 38.0, 0.75, 1.0, 0.04],
 "DoQ": [  120.0, 28.0, 0.5, 25.0, 20.0, 1.2, 3.0, 7.1, 12.0, 1.00, 10.0, 0.52, 22.0, 0.60, 6.0, 0.05],
}
_SCALE = np.array([25,12,0.35,14,12,0.45,0.35,0.30,3.0,0.05,2.5,0.10,9.0,0.12,1.2,0.03])

@dataclass(frozen=True)
class Scenario:
    sid: str
    protocol: str     # DoH, DoT, DoQ, or ALL
    family: str
    shift: dict       # feature -> shift in units of benign scale at severity 1
    description: str

def _s(**kw): return kw

SCENARIOS = {
 # --- the five scenarios of Table 32
 "S1-Timing": Scenario("S1-Timing","DoH","traffic_analysis",
    _s(iat_mean_ms=1.6, iat_skew=2.4, iat_std_ms=0.8),
    "inter-arrival distribution drifts right-skewed under timing inference"),
 "S2-Tunnel": Scenario("S2-Tunnel","ALL","tunneling",
    _s(qname_entropy_bits=3.2, subdomain_len_mean=3.4, unique_name_ratio=3.0, pkt_size_std=-1.0, query_rate_per_s=1.2),
    "high-entropy, long, mostly unique labels at a steady low rate"),
 "S4-Quantum": Scenario("S4-Quantum","DoH","protocol_exploit",
    _s(handshake_ms=2.2, proto_anomaly_score=4.0),
    "handshake with non-negotiated or malformed PQ key-exchange parameters"),
 "S5-Evasion": Scenario("S5-Evasion","ALL","ml_evasion",
    _s(qname_entropy_bits=1.5, subdomain_len_mean=1.4, unique_name_ratio=1.4, pkt_size_std=-0.4),
    "tunnel traffic perturbed toward benign statistics"),
 # --- extended protocol-aware scenarios (Sections 6.15.2 - 6.15.4)
 "DoH-MUX": Scenario("DoH-MUX","DoH","stream_multiplexing",
    _s(stream_count=3.0, payload_entropy_bits=1.4, pkt_size_std=1.2),
    "malicious queries hidden in one HTTP/2 stream among legitimate ones"),
 "DoH-HDR": Scenario("DoH-HDR","DoH","header_manipulation",
    _s(proto_anomaly_score=3.0, pkt_size_mean=1.0, payload_entropy_bits=0.8),
    "altered request headers and metadata"),
 "DoH-RESUME": Scenario("DoH-RESUME","DoH","session_reuse",
    _s(session_reuse_ratio=2.6, iat_std_ms=-0.7, query_rate_per_s=1.6),
    "long-lived resumed connection masking sustained malicious activity"),
 "DoT-RENEG": Scenario("DoT-RENEG","DoT","handshake_abuse",
    _s(handshake_ms=3.0, proto_anomaly_score=4.5, session_reuse_ratio=-1.2),
    "malformed handshake messages during renegotiation"),
 "DoT-CERT": Scenario("DoT-CERT","DoT","certificate_abuse",
    _s(handshake_ms=1.8, proto_anomaly_score=3.5),
    "inconsistent certificate chain during negotiation"),
 "DoT-TICKET": Scenario("DoT-TICKET","DoT","session_ticket_abuse",
    _s(session_reuse_ratio=3.0, proto_anomaly_score=2.4, handshake_ms=-0.8),
    "altered session-ticket parameters"),
 "DoQ-MIGRATE": Scenario("DoQ-MIGRATE","DoQ","connection_migration",
    _s(session_reuse_ratio=-1.6, handshake_ms=1.5, proto_anomaly_score=3.2, stream_count=1.0),
    "modified connection IDs and changing client addresses"),
 "DoQ-MUX": Scenario("DoQ-MUX","DoQ","stream_multiplexing",
    _s(stream_count=3.5, payload_entropy_bits=1.2, query_rate_per_s=1.4),
    "payload split over many concurrent streams"),
 "DoQ-VERNEG": Scenario("DoQ-VERNEG","DoQ","version_negotiation",
    _s(proto_anomaly_score=4.2, handshake_ms=2.0),
    "version negotiation steered to legacy parameters"),
}

def benign(proto: str, n: int, rng) -> np.ndarray:
    mu = np.array(_BENIGN[proto]); X = mu + rng.standard_normal((n, D)) * _SCALE
    X[:, FEATURES.index("proto_anomaly_score")] = np.abs(X[:, FEATURES.index("proto_anomaly_score")])
    return X

def attack(sid: str, proto: str, n: int, rng, severity: float = 1.0) -> np.ndarray:
    sc = SCENARIOS[sid]
    X = benign(proto, n, rng)
    for f, s in sc.shift.items():
        j = FEATURES.index(f)
        X[:, j] += severity * s * _SCALE[j] * (1 + 0.15 * rng.standard_normal(n))
    return X

def make_dataset(n_per_class: int, rng, scenarios=None, protocols=PROTOCOLS, severity=1.0):
    """Return X, y, proto_idx, scenario_idx. y=1 for attack."""
    scenarios = scenarios or list(SCENARIOS)
    Xs, ys, ps, ss = [], [], [], []
    for pi, p in enumerate(protocols):
        Xb = benign(p, n_per_class * 2, rng)
        Xs.append(Xb); ys.append(np.zeros(len(Xb))); ps.append(np.full(len(Xb), pi)); ss.append(np.full(len(Xb), -1))
        for si, sid in enumerate(scenarios):
            sc = SCENARIOS[sid]
            if sc.protocol not in ("ALL", p): continue
            Xa = attack(sid, p, n_per_class // 2, rng, severity)
            Xs.append(Xa); ys.append(np.ones(len(Xa))); ps.append(np.full(len(Xa), pi)); ss.append(np.full(len(Xa), si))
    return np.vstack(Xs), np.concatenate(ys), np.concatenate(ps).astype(int), np.concatenate(ss).astype(int)

def split(X, y, rng, frac=(0.6, 0.2, 0.2)):
    idx = rng.permutation(len(X)); a = int(frac[0] * len(X)); b = a + int(frac[1] * len(X))
    return idx[:a], idx[a:b], idx[b:]
