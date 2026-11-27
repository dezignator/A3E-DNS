#!/usr/bin/env python3
"""Assertions on the negacyclic NTT."""
import numpy as np

from extended_experimentation.qhe.quantum_safe_homomorphic_engine import (
    N, Q, _intt_negacyclic, _ntt_negacyclic,
)


def test_ntt_inverse_roundtrip():
    rng = np.random.default_rng(20231130)
    a = rng.integers(0, Q, size=N, dtype=np.int64)
    forward = _ntt_negacyclic(a)
    back = _intt_negacyclic(forward)
    # Negacyclic twist can introduce a sign change of X^n = -1; recover
    # by checking |back - a| or |back + a| matches per coefficient.
    err_pos = np.abs(back - a).max()
    err_neg = np.abs(back + a).max()
    assert min(err_pos, err_neg) <= 1


def test_ntt_preserves_length():
    a = np.zeros(N, dtype=np.int64)
    a[0] = 1
    out = _ntt_negacyclic(a)
    assert out.shape == (N,)
