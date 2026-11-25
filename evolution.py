"""AEE engine: Eqs. (119)-(122) of Chapter 6.

Euler-Maruyama integration on the Lie algebra:
    d xi = F(E, T, A) dt + Sigma dW
    Sigma = s_min + (s_max - s_min) exp(-lambda * int ||grad L||^2 ds)   (Eq. 122)
The thesis states the key-evolution schedule is heuristic and carries no
IND-CCA2 claim; this module follows that statement.
"""
import numpy as np
from .se3 import SE3State
from .entropy import kl_divergence, sigma_from_kl, EntropySource
from .controller import NeuralController

def diffusion_coefficient(cum_grad2, s_min, s_max, lam=1.0):
    return s_min + (s_max - s_min) * np.exp(-lam * cum_grad2)

class AEEEngine:
    def __init__(self, n=4, seed=None, controller_seed=0):
        self.state = SE3State(n); self.n = n
        self.ent = EntropySource(seed); self.ctrl = NeuralController(out_dim=6 * n, seed=controller_seed)
        self.t = 0.0; self.cum_grad2 = 0.0; self.history = []

    def update(self, features, p_traffic, p_baseline, dt=0.1, l_quantum_grad=0.0):
        kl = kl_divergence(p_traffic, p_baseline)
        sig = sigma_from_kl(kl)
        s_min, s_max = 0.5 * sig, 1.5 * sig
        self.cum_grad2 += float(l_quantum_grad) ** 2 * dt
        Sig = diffusion_coefficient(self.cum_grad2, s_min, s_max)
        drift = self.ctrl(features).reshape(self.n, 6) * 0.5
        noise = self.ent.normal((self.n, 6)) * np.sqrt(dt)
        xi = drift * dt + Sig * noise
        self.state.step(xi, 1.0); self.t += dt
        key, iv, cad = self.state.derive()
        rec = dict(t=self.t, kl=kl, sigma=float(Sig), cadence=float(cad), key_hex=key[:4].hex())
        self.history.append(rec)
        return key, iv, cad, rec
