"""Unit tests for :mod:`src.models.qhe_ntt`.

Covers the Number Theoretic Transform used for Ring-LWE polynomial
multiplication (§6.5.1). The core property is that NTT multiplication
agrees with schoolbook negacyclic multiplication in the ring
``Z_q[x] / (x^n + 1)``:

    ntt_multiply(a, b) == negacyclic_multiply(a, b)  (mod q)
"""

from __future__ import annotations

import numpy as np
import pytest

from src.models.qhe_ntt import (
    NTTContext,
    negacyclic_multiply,
    ntt_forward,
    ntt_inverse,
    ntt_multiply,
)


# ---------------------------------------------------------------- small config
@pytest.fixture
def small_ntt_ctx() -> NTTContext:
    """A small NTT context for fast tests."""
    return NTTContext(n=16, q=17)


# ---------------------------------------------------------------- forward/inverse
def test_ntt_roundtrip_small(small_ntt_ctx):
    """``inverse(forward(a)) == a``."""
    rng = np.random.default_rng(20261130)
    a = rng.integers(0, 17, size=16, dtype=np.int64)
    a_hat = ntt_forward(a, n=16, q=17, context=small_ntt_ctx)
    a_back = ntt_inverse(a_hat, n=16, q=17, context=small_ntt_ctx)
    np.testing.assert_array_equal(a_back % 17, a % 17)


def test_ntt_roundtrip_thesis_params():
    """Same round-trip on the thesis parameters ``n=256, q=4096``.

    ``q=4096`` is not prime, so the negacyclic NTT requires a unit of
    order ``2n=512`` modulo ``q``. The NTTContext finds it.
    """
    ctx = NTTContext(n=256, q=4096)
    rng = np.random.default_rng(20261131)
    a = rng.integers(0, 4096, size=256, dtype=np.int64)
    a_hat = ntt_forward(a, n=256, q=4096, context=ctx)
    a_back = ntt_inverse(a_hat, n=256, q=4096, context=ctx)
    np.testing.assert_array_equal(a_back % 4096, a % 4096)


# ---------------------------------------------------------------- multiplication
def test_ntt_multiply_matches_schoolbook_small(small_ntt_ctx):
    rng = np.random.default_rng(20261132)
    a = rng.integers(0, 17, size=16, dtype=np.int64)
    b = rng.integers(0, 17, size=16, dtype=np.int64)
    out_ntt = ntt_multiply(a, b, n=16, q=17, context=small_ntt_ctx)
    out_ref = negacyclic_multiply(a, b, q=17)
    np.testing.assert_array_equal(out_ntt % 17, out_ref % 17)


def test_ntt_multiply_zero():
    """``a · 0 = 0`` in the ring."""
    ctx = NTTContext(n=16, q=17)
    rng = np.random.default_rng(20261133)
    a = rng.integers(0, 17, size=16, dtype=np.int64)
    b = np.zeros(16, dtype=np.int64)
    out = ntt_multiply(a, b, n=16, q=17, context=ctx)
    np.testing.assert_array_equal(out % 17, np.zeros(16, dtype=np.int64))


def test_ntt_multiply_one():
    """``a · 1 = a`` in the ring."""
    ctx = NTTContext(n=16, q=17)
    rng = np.random.default_rng(20261134)
    a = rng.integers(0, 17, size=16, dtype=np.int64)
    b = np.zeros(16, dtype=np.int64)
    b[0] = 1
    out = ntt_multiply(a, b, n=16, q=17, context=ctx)
    np.testing.assert_array_equal(out % 17, a % 17)


# ---------------------------------------------------------------- guards
def test_ntt_rejects_non_power_of_two_n():
    with pytest.raises(ValueError):
        NTTContext(n=10, q=17)


def test_ntt_rejects_q_too_small():
    with pytest.raises(ValueError):
        NTTContext(n=16, q=1)


def test_ntt_multiply_rejects_shape_mismatch():
    ctx = NTTContext(n=16, q=17)
    a = np.zeros(16, dtype=np.int64)
    b = np.zeros(8, dtype=np.int64)
    with pytest.raises(ValueError):
        ntt_multiply(a, b, n=16, q=17, context=ctx)


# ---------------------------------------------------------------- determinism
def test_ntt_multiply_deterministic():
    ctx = NTTContext(n=16, q=17)
    rng = np.random.default_rng(20261135)
    a = rng.integers(0, 17, size=16, dtype=np.int64)
    b = rng.integers(0, 17, size=16, dtype=np.int64)
    out1 = ntt_multiply(a, b, n=16, q=17, context=ctx)
    out2 = ntt_multiply(a, b, n=16, q=17, context=ctx)
    np.testing.assert_array_equal(out1, out2)


# ---------------------------------------------------------------- negacyclic sanity
def test_negacyclic_multiply_x_times_x():
    """In ``Z_q[x]/(x^n + 1)``, ``x · x = x²`` if n ≥ 3, else a wraparound."""
    q = 17
    n = 16
    a = np.zeros(n, dtype=np.int64)
    a[1] = 1  # polynomial x
    out = negacyclic_multiply(a, a, q=q)
    expected = np.zeros(n, dtype=np.int64)
    expected[2] = 1  # polynomial x²
    np.testing.assert_array_equal(out, expected)


def test_negacyclic_multiply_xn_wraps_negatively():
    """``x^(n-1) · x = x^n = -1`` in the ring."""
    q = 17
    n = 16
    a = np.zeros(n, dtype=np.int64)
    a[n - 1] = 1  # polynomial x^(n-1)
    b = np.zeros(n, dtype=np.int64)
    b[1] = 1  # polynomial x
    out = negacyclic_multiply(a, b, q=q)
    expected = np.zeros(n, dtype=np.int64)
    expected[0] = q - 1  # -1 mod q
    np.testing.assert_array_equal(out, expected)
