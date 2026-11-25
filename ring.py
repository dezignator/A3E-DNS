"""Polynomial ring R_q = Z_q[x]/(x^n + 1) (Section 6.5.1).

Three parameter sets are provided because Chapter 6 states two
incompatible ones (Table 27: n=1024, q=3329; Table 34a: n=256, q=4096).
The NTT set is our own NTT-friendly choice. All sets are TOY parameters:
they are chosen to study noise growth and structure, not for security.
"""
from dataclasses import dataclass
import numpy as np

@dataclass(frozen=True)
class RingParams:
    name: str; n: int; q: int; t: int; sigma: float = 1.58
    @property
    def delta(self): return self.q // self.t

PARAM_SETS = {
 "thesis_table34a": RingParams("thesis_table34a", 256, 4096, 2),
 "thesis_table27":  RingParams("thesis_table27", 1024, 3329, 2),
 "ntt_n256":        RingParams("ntt_n256", 256, 786433, 256),
}

def negacyclic_mul(a, b, q):
    n = len(a)
    c = np.convolve(a.astype(np.int64), b.astype(np.int64))
    r = c[:n].copy(); r[: len(c) - n] -= c[n:]
    return np.mod(r, q)

def _find_psi(n, q):
    assert (q - 1) % (2 * n) == 0, "q must be 1 mod 2n for the negacyclic NTT"
    for g in range(2, q):
        psi = pow(g, (q - 1) // (2 * n), q)
        if pow(psi, n, q) == q - 1: return psi
    raise ValueError

def _ntt(a, w, q):
    n = len(a)
    if n == 1: return a
    ev = _ntt(a[0::2], w * w % q, q); od = _ntt(a[1::2], w * w % q, q)
    out = [0] * n; x = 1
    for k in range(n // 2):
        t = x * od[k] % q; out[k] = (ev[k] + t) % q; out[k + n // 2] = (ev[k] - t) % q; x = x * w % q
    return out

def ntt_negacyclic_mul(a, b, q):
    n = len(a); psi = _find_psi(n, q); w = psi * psi % q; winv = pow(w, -1, q); ninv = pow(n, -1, q); psiinv = pow(psi, -1, q)
    pa = [int(a[i]) * pow(psi, i, q) % q for i in range(n)]; pb = [int(b[i]) * pow(psi, i, q) % q for i in range(n)]
    fa, fb = _ntt(pa, w, q), _ntt(pb, w, q)
    fc = [x * y % q for x, y in zip(fa, fb)]
    c = _ntt(fc, winv, q)
    return np.array([c[i] * ninv % q * pow(psiinv, i, q) % q for i in range(n)], dtype=np.int64)
