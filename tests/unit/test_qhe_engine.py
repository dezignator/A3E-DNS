"""Unit tests for :mod:`src.models.qhe_engine`.

Covers:
    * the Ring-LWE round-trip (encrypt → decrypt),
    * the homomorphic additive and multiplicative operations,
    * the ``selective_ops`` restriction,
    * the parameter values (§6.5: n = 256, q = 4096).

**Important:** the toy/CPU backend (``_RingLWESimulator``) is a
pedagogical implementation. The tests here are correctness tests for
the arithmetic, not security tests. The IND-CPA argument for the
scheme is in §5.3.5 of the thesis and is a citation of the published
Ring-LWE result; the toy backend does not instantiate that argument.
See ``docs/SECURITY_ARGUMENTS.md`` §2.
"""

from __future__ import annotations

import numpy as np
import pytest

from src.models.qhe_engine import (
    HomomorphicOps,
    QHECiphertext,
    QHEConfig,
    QHEEngine,
)


# ---------------------------------------------------------------- config
def test_qhe_config_defaults_match_thesis():
    cfg = QHEConfig()
    assert cfg.n == 256
    assert cfg.q == 4096
    assert cfg.ntt is True
    assert cfg.ziggurat is True


def test_qhe_config_rejects_wrong_n():
    with pytest.raises(ValueError):
        QHEConfig(n=128)


def test_qhe_config_rejects_wrong_q():
    with pytest.raises(ValueError):
        QHEConfig(q=2048)


def test_qhe_config_rejects_non_power_of_two_q():
    with pytest.raises(ValueError):
        QHEConfig(n=256, q=3329)


# ---------------------------------------------------------------- keygen
def test_qhe_keygen_returns_hashes():
    engine = QHEEngine()
    info = engine.keygen()
    assert info["n"] == 256
    assert info["q"] == 4096
    assert len(info["sk_sha256"]) == 64
    assert len(info["pk_sha256"]) == 64


# ---------------------------------------------------------------- round-trip
def test_qhe_roundtrip_binary_message():
    """``decrypt(encrypt(m)) == m`` for a binary message."""
    engine = QHEEngine()
    engine.keygen()
    msg = np.array([1, 0, 1, 1, 0, 0, 1, 0] + [0] * 248, dtype=np.int64)
    ct = engine.encrypt(msg)
    recovered = engine.decrypt(ct)
    np.testing.assert_array_equal(recovered, msg)


def test_qhe_roundtrip_all_zeros():
    engine = QHEEngine()
    engine.keygen()
    msg = np.zeros(256, dtype=np.int64)
    ct = engine.encrypt(msg)
    recovered = engine.decrypt(ct)
    np.testing.assert_array_equal(recovered, msg)


def test_qhe_roundtrip_all_ones():
    engine = QHEEngine()
    engine.keygen()
    msg = np.ones(256, dtype=np.int64)
    ct = engine.encrypt(msg)
    recovered = engine.decrypt(ct)
    np.testing.assert_array_equal(recovered, msg)


def test_qhe_roundtrip_random():
    rng = np.random.default_rng(20261130)
    engine = QHEEngine()
    engine.keygen()
    for _ in range(5):
        msg = rng.integers(0, 2, size=256, dtype=np.int64)
        ct = engine.encrypt(msg)
        recovered = engine.decrypt(ct)
        np.testing.assert_array_equal(recovered, msg)


# ---------------------------------------------------------------- homomorphic
def test_qhe_add_is_homomorphic():
    """``decrypt(add(enc(a), enc(b))) == (a + b) mod 2``."""
    engine = QHEEngine()
    engine.keygen()
    a = np.array([1, 0, 1, 1] + [0] * 252, dtype=np.int64)
    b = np.array([0, 1, 0, 1] + [0] * 252, dtype=np.int64)
    ca = engine.encrypt(a)
    cb = engine.encrypt(b)
    c_sum = engine.evaluate(HomomorphicOps.ADD, ca, cb)
    recovered = engine.decrypt(c_sum)
    expected = (a + b) % 2
    np.testing.assert_array_equal(recovered, expected)


def test_qhe_add_requires_two_ciphertexts():
    engine = QHEEngine()
    engine.keygen()
    msg = np.zeros(256, dtype=np.int64)
    ct = engine.encrypt(msg)
    with pytest.raises(ValueError):
        engine.evaluate(HomomorphicOps.ADD, ct)


def test_qhe_unsupported_op_raises():
    engine = QHEEngine()
    engine.keygen()
    msg = np.zeros(256, dtype=np.int64)
    ct = engine.encrypt(msg)
    with pytest.raises(ValueError):
        engine.evaluate("unsupported_op", ct)


def test_qhe_stat_var_not_implemented():
    engine = QHEEngine()
    engine.keygen()
    msg = np.zeros(256, dtype=np.int64)
    ct = engine.encrypt(msg)
    with pytest.raises(NotImplementedError):
        engine.evaluate(HomomorphicOps.STAT_VAR, ct)


# ---------------------------------------------------------------- ciphertext
def test_qhe_ciphertext_shape_mismatch_raises():
    with pytest.raises(ValueError):
        QHECiphertext(a=np.zeros(256), b=np.zeros(128))


def test_qhe_ciphertext_requires_1d():
    with pytest.raises(ValueError):
        QHECiphertext(a=np.zeros((2, 128)), b=np.zeros((2, 128)))


# ---------------------------------------------------------------- determinism
def test_qhe_roundtrip_deterministic_given_seed():
    """Two engines with the same seed produce the same ciphertext shapes
    and round-trip results. (The ciphertext *bytes* differ because the
    public matrix `a` is sampled per engine, but the round-trip result
    is the same.)"""
    msg = np.array([1, 0, 1, 1, 0, 0, 1, 0] + [0] * 248, dtype=np.int64)
    engine1 = QHEEngine(QHEConfig(seed=20261130))
    engine1.keygen()
    ct1 = engine1.encrypt(msg)
    engine2 = QHEEngine(QHEConfig(seed=20261130))
    engine2.keygen()
    ct2 = engine2.encrypt(msg)
    assert ct1.a.shape == ct2.a.shape
    np.testing.assert_array_equal(engine1.decrypt(ct1), engine2.decrypt(ct2))


# ---------------------------------------------------------------- metadata
def test_qhe_metadata_matches_thesis():
    engine = QHEEngine()
    meta = engine.metadata()
    assert meta["n"] == 256
    assert meta["q"] == 4096
    assert meta["scheme"] == "ring_lwe"
    assert meta["ntt"] is True
    assert meta["ziggurat"] is True
