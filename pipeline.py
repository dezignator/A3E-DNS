"""Composite pipeline P = S_eBPF o F_QHE o AFL o M_sandbox (Eq. 117, Section 6.3.3).

Composition order: the sandbox stage acts first, then the federated detector, then the encrypted-domain
statistics, then the data-plane metadata stage. Each stage can be switched off for ablation runs.
"""
from dataclasses import dataclass, field
import numpy as np
from .sandbox import SandboxMDP, value_iteration, PROTOCOL_ACTIONS
from .sandbox.mdp import ACTIONS, STATES
from .qhe import EncryptedHistogram, chi_square_from_counts

@dataclass
class A3EPipeline:
    detector: object                    # needs predict_proba on standardised features
    mu: np.ndarray
    sd: np.ndarray
    qhe_hist: EncryptedHistogram = None
    baseline_counts: np.ndarray = None
    chi2_critical: float = 30.58        # chi-square 0.99 quantile, 15 degrees of freedom (16 bins)
    threshold: float = 0.5
    sandbox_policy: np.ndarray = field(default_factory=lambda: value_iteration(SandboxMDP())[1])
    state: int = 0
    log: list = field(default_factory=list)

    # --- stage 1: sandbox (M_sandbox). Routes by current state; a suspicious state isolates the flow.
    def _sandbox(self, proto):
        a = int(self.sandbox_policy[self.state]); return ACTIONS[a], PROTOCOL_ACTIONS[proto].get(ACTIONS[a], "none")
    # --- stage 2: AFL detector
    def _afl(self, X):
        s = self.detector.predict_proba((X - self.mu) / self.sd); return s, float(s.mean())
    # --- stage 3: QHE encrypted statistic over qname-entropy values of the window (16 bins, counts must stay < t)
    def _qhe(self, X, j_entropy=6):
        if self.qhe_hist is None: return None
        ct = self.qhe_hist.report(np.clip(X[:, j_entropy], 0, 5.99)); return ct
    # --- stage 4: eBPF/P4 style metadata (no payload)
    def _meta(self, X, proto):
        return dict(proto=proto, n=len(X), mean_rate=float(X[:, 8].mean()), mean_size=float(X[:, 0].mean()))

    def process(self, X, proto):
        act, proto_act = self._sandbox(proto); s, m = self._afl(X); ct = self._qhe(X); meta = self._meta(X, proto)
        flagged = m > self.threshold
        self.state = 1 if flagged and self.state == 0 else (0 if (not flagged and self.state == 1) else self.state)
        rec = dict(sandbox_action=act, protocol_action=proto_act, mean_score=m, flagged=bool(flagged), state=STATES[self.state], meta=meta, ciphertext=ct)
        self.log.append(rec); return rec

    def encrypted_verdict(self, cts):
        """Authorised party: aggregate ciphertexts, decrypt the histogram, run the chi-square test."""
        agg = self.qhe_hist.aggregate(cts); dec = self.qhe_hist.open(agg); chi = chi_square_from_counts(dec, self.baseline_counts)
        return chi, chi > self.chi2_critical
