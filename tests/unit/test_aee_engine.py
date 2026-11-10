"""Unit tests for :mod:`src.models.aee_engine`.

Covers:
    * the engine's construction and config validation,
    * the ``initialize`` / ``step`` lifecycle,
    * the strict positivity of ``σ(t)`` (Eq. 122, §6.4.4),
    * the session-key length (256 bits, §6.4.2),
    * the IV length and the cadence range.

No security property is tested here. The AEE schedule is a heuristic
construction (§6.4.1, §6.4.4); the formal security argument is reserved
for the KEM layer (Proposition 1, §5.2.6). See
``docs/SECURITY_ARGUMENTS.md`` §3.
"""

from __future__ import annotations

import numpy as np
import pytest

from src.models.aee_engine import (
    AEEEngine,
    AEEEngineConfig,
    AEEState,
    derive_iv_and_cadence,
    kdf_256,
)


# ---------------------------------------------------------------- config
def test_aee_config_defaults():
    cfg = AEEEngineConfig()
    assert cfg.se3_dim == 1
    assert cfg.key_bits == 256
    assert cfg.state_vector_dim == 64
    assert cfg.sigma_min > 0.0
    assert cfg.sigma_max > cfg.sigma_min


def test_aee_config_rejects_bad_key_bits():
    with pytest.raises(ValueError):
        AEEEngineConfig(key_bits=128)


def test_aee_config_rejects_invalid_sigma_range():
    with pytest.raises(ValueError):
        AEEEngineConfig(sigma_min=0.0)
    with pytest.raises(ValueError):
        AEEEngineConfig(sigma_min=1e-2, sigma_max=1e-3)


def test_aee_config_rejects_bad_cadence_range():
    with pytest.raises(ValueError):
        AEEEngineConfig(cadence_seconds_range=(0.0, 10.0))
    with pytest.raises(ValueError):
        AEEEngineConfig(cadence_seconds_range=(10.0, 5.0))


# ---------------------------------------------------------------- KDF
def test_kdf_256_returns_32_bytes():
    out = kdf_256(b"material")
    assert len(out) == 32


def test_kdf_256_context_changes_output():
    a = kdf_256(b"material", context=b"ctx-a")
    b = kdf_256(b"material", context=b"ctx-b")
    assert a != b


def test_kdf_256_deterministic():
    a = kdf_256(b"material")
    b = kdf_256(b"material")
    assert a == b


# ---------------------------------------------------------------- IV/cadence
def test_derive_iv_and_cadence_returns_bounded_cadence():
    rng = np.random.default_rng(0)
    for _ in range(20):
        t = rng.normal(0.0, 1.0, size=3)
        iv, cadence = derive_iv_and_cadence(t, cadence_seconds_range=(5.0, 60.0))
        assert 12 == len(iv)  # 96 bits
        assert 5.0 <= cadence < 60.0


def test_derive_iv_and_cadence_deterministic():
    t = np.array([0.1, -0.2, 0.3])
    iv1, c1 = derive_iv_and_cadence(t)
    iv2, c2 = derive_iv_and_cadence(t)
    assert iv1 == iv2
    assert c1 == c2


# ---------------------------------------------------------------- engine lifecycle
def test_engine_initialize_state():
    engine = AEEEngine(AEEEngineConfig(se3_dim=2))
    state = engine.initialize()
    assert isinstance(state, AEEState)
    assert state.R.shape == (2, 3, 3)
    assert state.t.shape == (2, 3)
    assert len(state.session_key) == 32  # 256 bits
    assert len(state.iv) == 12  # 96 bits
    assert state.step == 0
    assert state.entropy_trace == ()


def test_engine_state_raises_before_initialize():
    engine = AEEEngine(AEEEngineConfig(se3_dim=1))
    with pytest.raises(RuntimeError):
        _ = engine.state


def test_engine_step_advances_state():
    engine = AEEEngine(AEEEngineConfig(se3_dim=1))
    engine.initialize()
    features = np.zeros(64)
    state = engine.step(features, kl_divergence=0.1)
    assert state.step == 1
    assert len(state.entropy_trace) == 1
    assert state.entropy_trace[0] == 0.1


def test_engine_step_rejects_negative_kl():
    engine = AEEEngine(AEEEngineConfig(se3_dim=1))
    engine.initialize()
    with pytest.raises(ValueError):
        engine.step(np.zeros(64), kl_divergence=-0.1)


def test_engine_rollback_resets_state():
    engine = AEEEngine(AEEEngineConfig(se3_dim=1))
    engine.initialize()
    engine.step(np.zeros(64), kl_divergence=0.5)
    assert engine.state.step == 1
    engine.rollback()
    assert engine.state.step == 0


# ---------------------------------------------------------------- sigma
def test_sigma_is_strictly_positive():
    """``σ(t) > 0`` for every input, per Eq. 122 and §6.4.4."""
    engine = AEEEngine(AEEEngineConfig(se3_dim=1))
    for kl in (0.0, 0.1, 1.0, 10.0, 1000.0):
        sigma = engine._sigma(kl)
        assert sigma > 0.0


def test_sigma_is_bounded_by_sigma_max():
    engine = AEEEngine(AEEEngineConfig(se3_dim=1))
    for kl in (0.0, 0.1, 1.0, 10.0, 1000.0):
        sigma = engine._sigma(kl)
        assert sigma <= engine.config.sigma_max + 1e-12


def test_sigma_monotone_in_kl():
    """``σ(kl)`` is non-decreasing in ``kl``."""
    engine = AEEEngine(AEEEngineConfig(se3_dim=1))
    kls = [0.0, 0.1, 1.0, 10.0, 100.0]
    sigmas = [engine._sigma(kl) for kl in kls]
    for a, b in zip(sigmas, sigmas[1:]):
        assert b >= a - 1e-12


# ---------------------------------------------------------------- session key
def test_session_key_is_256_bits():
    engine = AEEEngine(AEEEngineConfig(se3_dim=1))
    state = engine.initialize()
    assert len(state.session_key) == 32


def test_session_key_changes_after_step():
    engine = AEEEngine(AEEEngineConfig(se3_dim=1))
    engine.initialize()
    key0 = engine.state.session_key
    engine.step(np.zeros(64), kl_divergence=0.5)
    key1 = engine.state.session_key
    assert key0 != key1


# ---------------------------------------------------------------- controller
def test_engine_with_custom_controller():
    """A custom controller that returns a fixed increment produces a
    deterministic state trajectory."""

    def controller(features):
        return np.zeros((1, 6))

    engine = AEEEngine(AEEEngineConfig(se3_dim=1), controller=controller)
    engine.initialize()
    state = engine.step(np.zeros(64), kl_divergence=0.0)
    # With a zero controller and zero KL, the stochastic term is still
    # non-zero (σ(t) > 0 by design). But the state should still be a
    # valid SE(3) element.
    R = state.R[0]
    np.testing.assert_allclose(R @ R.T, np.eye(3), atol=1e-10)
    assert np.isclose(np.linalg.det(R), 1.0, atol=1e-10)


def test_engine_rejects_controller_with_wrong_shape():
    def bad_controller(features):
        return np.zeros((2, 6))  # wrong shape for se3_dim=1

    engine = AEEEngine(AEEEngineConfig(se3_dim=1), controller=bad_controller)
    engine.initialize()
    with pytest.raises(ValueError):
        engine.step(np.zeros(64), kl_divergence=0.0)
