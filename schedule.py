"""Adaptive learning-rate schedule, Eq. (133) of Section 6.9.3 (base rate 6.5 %).

eta_t = eta_0 * exp(-int_0^t gamma(s) ||grad L(theta_s)||^2 ds) * I{PLATEAU(t) < delta}
The text says the indicator "caused a decay" during a plateau. A literal product would set eta to 0 whenever
the indicator is 0, so we read it as: the exponential decay accumulates only while the loss plateau is active
and the rate is left at eta_0 otherwise (flagged in docs/v2/08_consistency_audit.md).
"""
import numpy as np

class AdaptiveLR:
    def __init__(self, eta0=0.065, gamma=1.0, delta=1e-3, window=5):
        self.eta0, self.gamma, self.delta, self.w = eta0, gamma, delta, window; self.acc = 0.0; self.losses = []

    def plateau(self):
        if len(self.losses) < self.w + 1: return False
        return abs(self.losses[-1] - self.losses[-1 - self.w]) / self.w < self.delta

    def step(self, loss, grad_norm, dt=1.0):
        self.losses.append(float(loss))
        if self.plateau(): self.acc += self.gamma * float(grad_norm) ** 2 * dt
        return self.eta0 * np.exp(-self.acc)
