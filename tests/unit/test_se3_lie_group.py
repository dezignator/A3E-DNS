"""Unit tests for :mod:`src.utils.se3_lie_group`.

Covers the SE(3) exp/log round-trip, the group composition/inverse
identities, and the projection used by the AEE engine. These
properties are what the SE(3)ⁿ state evolution in §6.4.2 relies on:

    * ``exp`` and ``log`` are inverse maps (mod 2π).
    * composition is associative.
    * ``g · g⁻¹ = identity``.

No security property is tested here (the SE(3) module has no security
claim; see ``docs/SECURITY_ARGUMENTS.md`` §3).
"""

from __future__ import annotations

import numpy as np
import pytest

from src.utils.se3_lie_group import (
    se3_compose,
    se3_exp,
    se3_inverse,
    se3_log,
    se3n_compose,
    se3n_exp,
    se3n_identity,
    se3n_inverse,
    se3n_log,
    se3n_project,
    se3n_random,
)


# ---------------------------------------------------------------- fixtures
@pytest.fixture
def small_omega() -> np.ndarray:
    rng = np.random.default_rng(20261130)
    return rng.normal(0.0, 0.1, size=3)


@pytest.fixture
def small_v() -> np.ndarray:
    rng = np.random.default_rng(20261131)
    return rng.normal(0.0, 0.1, size=3)


# ---------------------------------------------------------------- exp/log
def test_se3_exp_returns_rotation_and_translation(small_omega, small_v):
    R, t = se3_exp(small_omega, small_v)
    assert R.shape == (3, 3)
    assert t.shape == (3,)
    # R must be a valid rotation: R Rᵀ = I, det(R) = 1
    np.testing.assert_allclose(R @ R.T, np.eye(3), atol=1e-10)
    assert np.isclose(np.linalg.det(R), 1.0, atol=1e-10)


def test_se3_exp_log_roundtrip_small(small_omega, small_v):
    """``log(exp(ξ)) == ξ`` for ``ξ`` in the small-angle regime."""
    R, t = se3_exp(small_omega, small_v)
    omega2, v2 = se3_log(R, t)
    np.testing.assert_allclose(omega2, small_omega, atol=1e-8)
    np.testing.assert_allclose(v2, small_v, atol=1e-8)


def test_se3_exp_at_identity():
    """``exp(0) == identity``."""
    R, t = se3_exp(np.zeros(3), np.zeros(3))
    np.testing.assert_allclose(R, np.eye(3), atol=1e-12)
    np.testing.assert_allclose(t, np.zeros(3), atol=1e-12)


# ---------------------------------------------------------------- group ops
def test_se3_compose_associative(small_omega, small_v):
    """``(g1 · g2) · g3 == g1 · (g2 · g3)``."""
    rng = np.random.default_rng(20261132)
    ws = rng.normal(0.0, 0.1, size=(3, 3))
    vs = rng.normal(0.0, 0.1, size=(3, 3))
    gs = [se3_exp(ws[i], vs[i]) for i in range(3)]

    (R1, t1), (R2, t2), (R3, t3) = gs
    R12, t12 = se3_compose(R1, t1, R2, t2)
    R_left, t_left = se3_compose(R12, t12, R3, t3)
    R23, t23 = se3_compose(R2, t2, R3, t3)
    R_right, t_right = se3_compose(R1, t1, R23, t23)
    np.testing.assert_allclose(R_left, R_right, atol=1e-10)
    np.testing.assert_allclose(t_left, t_right, atol=1e-10)


def test_se3_inverse_is_inverse(small_omega, small_v):
    """``g · g⁻¹ == identity``."""
    R, t = se3_exp(small_omega, small_v)
    R_inv, t_inv = se3_inverse(R, t)
    R_id, t_id = se3_compose(R, t, R_inv, t_inv)
    np.testing.assert_allclose(R_id, np.eye(3), atol=1e-10)
    np.testing.assert_allclose(t_id, np.zeros(3), atol=1e-10)


# ---------------------------------------------------------------- SE(3)ⁿ
def test_se3n_identity_shape():
    R, t = se3n_identity(4)
    assert R.shape == (4, 3, 3)
    assert t.shape == (4, 3)
    for i in range(4):
        np.testing.assert_allclose(R[i], np.eye(3), atol=1e-12)
        np.testing.assert_allclose(t[i], np.zeros(3), atol=1e-12)


def test_se3n_exp_log_roundtrip():
    """``se3n_log(se3n_exp(ξ)) == ξ`` for small ``ξ``."""
    rng = np.random.default_rng(20261133)
    xi = rng.normal(0.0, 0.05, size=(4, 6))
    R, t = se3n_exp(xi)
    xi2 = se3n_log(R, t)
    np.testing.assert_allclose(xi2, xi, atol=1e-8)


def test_se3n_compose_inverse():
    rng = np.random.default_rng(20261134)
    xi = rng.normal(0.0, 0.05, size=(4, 6))
    R, t = se3n_exp(xi)
    R_inv, t_inv = se3n_inverse(R, t)
    R_id, t_id = se3n_compose(R, t, R_inv, t_inv)
    for i in range(4):
        np.testing.assert_allclose(R_id[i], np.eye(3), atol=1e-10)
        np.testing.assert_allclose(t_id[i], np.zeros(3), atol=1e-10)


def test_se3n_project_identity():
    """For vector-form input, ``se3n_project`` is the identity."""
    rng = np.random.default_rng(20261135)
    xi = rng.normal(0.0, 0.1, size=(3, 6))
    out = se3n_project(xi)
    np.testing.assert_allclose(out, xi, atol=1e-15)


def test_se3n_random_is_se3():
    rng = np.random.default_rng(20261136)
    R, t = se3n_random(rng, n=3)
    assert R.shape == (3, 3, 3)
    assert t.shape == (3, 3)
    for i in range(3):
        np.testing.assert_allclose(R[i] @ R[i].T, np.eye(3), atol=1e-10)
        assert np.isclose(np.linalg.det(R[i]), 1.0, atol=1e-10)


# ---------------------------------------------------------------- guards
def test_se3_exp_rejects_wrong_shapes():
    with pytest.raises(ValueError):
        se3_exp(np.zeros(4), np.zeros(3))


def test_se3_log_rejects_wrong_shapes():
    with pytest.raises(ValueError):
        se3_log(np.eye(4), np.zeros(3))


def test_se3n_identity_rejects_zero():
    with pytest.raises(ValueError):
        se3n_identity(0)


def test_se3n_exp_rejects_wrong_shape():
    with pytest.raises(ValueError):
        se3n_exp(np.zeros((4, 5)))
