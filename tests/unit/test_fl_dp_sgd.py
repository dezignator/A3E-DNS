"""Unit tests for :mod:`src.models.fl_dp_sgd`.

Covers:
    * the DP-SGD aggregate step,
    * the noise calibration (RDP accountant),
    * the epsilon bound at the thesis value (ε = 0.68),
    * the clipping bound.

**Important:** these are correctness tests for the DP mechanism, not
security proofs. The DP guarantee is the standard approximate-DP
condition (Eq. 37, §4.6.2; Eq. 129, §6.6.5), cited from Abadi et al.
See ``docs/SECURITY_ARGUMENTS.md`` §2 for the IND-CPA/IND-CCA2
distinction (which does not apply here; the DP mechanism is separate
from the HE layer).
"""

from __future__ import annotations

import numpy as np
import pytest

from src.models.fl_dp_sgd import (
    DPConfig,
    DPSGDMechanism,
    clip_update,
    inject_gaussian_noise,
)


# ---------------------------------------------------------------- config
def test_dp_config_defaults_match_thesis():
    cfg = DPConfig()
    assert cfg.epsilon == 0.68
    assert cfg.delta == 1e-5
    assert cfg.clipping_norm == 1.0
    assert cfg.rounds == 100


def test_dp_config_rejects_bad_epsilon():
    with pytest.raises(ValueError):
        DPConfig(epsilon=0.0)
    with pytest.raises(ValueError):
        DPConfig(epsilon=-0.1)


def test_dp_config_rejects_bad_delta():
    with pytest.raises(ValueError):
        DPConfig(delta=0.0)
    with pytest.raises(ValueError):
        DPConfig(delta=1.0)


def test_dp_config_rejects_bad_clipping_norm():
    with pytest.raises(ValueError):
        DPConfig(clipping_norm=0.0)
    with pytest.raises(ValueError):
        DPConfig(clipping_norm=-1.0)


def test_dp_config_rejects_bad_sampling_rate():
    with pytest.raises(ValueError):
        DPConfig(sampling_rate=0.0)
    with pytest.raises(ValueError):
        DPConfig(sampling_rate=1.5)


# ---------------------------------------------------------------- clip
def test_clip_update_small_vector():
    v = np.array([0.3, 0.4, 0.0])  # norm 0.5
    out = clip_update(v, C=1.0)
    np.testing.assert_array_equal(out, v)


def test_clip_update_large_vector():
    v = np.array([3.0, 4.0, 0.0])  # norm 5
    out = clip_update(v, C=1.0)
    assert np.isclose(np.linalg.norm(out), 1.0)
    np.testing.assert_allclose(out / 1.0, v / 5.0)


def test_clip_update_rejects_non_positive_C():
    with pytest.raises(ValueError):
        clip_update(np.zeros(3), C=0.0)


# ---------------------------------------------------------------- noise
def test_inject_gaussian_noise_preserves_shape():
    rng = np.random.default_rng(0)
    agg = np.zeros(8)
    out = inject_gaussian_noise(
        agg, noise_multiplier=4.0, clipping_norm=1.0, n_clients=10, rng=rng
    )
    assert out.shape == agg.shape


def test_inject_gaussian_noise_rejects_zero_clients():
    rng = np.random.default_rng(0)
    with pytest.raises(ValueError):
        inject_gaussian_noise(
            np.zeros(4), noise_multiplier=4.0, clipping_norm=1.0, n_clients=0, rng=rng
        )


def test_inject_gaussian_noise_scale_decreases_with_clients():
    """With more clients, the noise scale decreases (as σ·C/K)."""
    rng1 = np.random.default_rng(0)
    rng2 = np.random.default_rng(0)
    agg = np.zeros(64)
    out_small = inject_gaussian_noise(
        agg, noise_multiplier=4.0, clipping_norm=1.0, n_clients=10, rng=rng1
    )
    out_large = inject_gaussian_noise(
        agg, noise_multiplier=4.0, clipping_norm=1.0, n_clients=100, rng=rng2
    )
    # The 100-client run should have a smaller L2 norm on average; the
    # single-run comparison is noisy but the standard deviation should
    # be proportional to 1/K.
    assert np.std(out_large) < np.std(out_small)


# ---------------------------------------------------------------- accountant
def test_epsilon_at_decreases_with_noise_multiplier():
    mech = DPSGDMechanism(DPConfig())
    eps_lo = mech.epsilon_at(1.0)
    eps_hi = mech.epsilon_at(10.0)
    assert eps_hi < eps_lo


def test_epsilon_at_increases_with_rounds():
    small = DPSGDMechanism(DPConfig(rounds=10, noise_multiplier=4.0))
    large = DPSGDMechanism(DPConfig(rounds=100, noise_multiplier=4.0))
    assert large.epsilon_at(4.0) > small.epsilon_at(4.0)


def test_calibrate_finds_noise_multiplier():
    """Calibrating to ε = 0.68 should return a positive multiplier."""
    mech = DPSGDMechanism(DPConfig(epsilon=0.68, rounds=100))
    nm = mech.calibrate()
    assert nm > 0.0
    # The calibrated multiplier should achieve at most ε = 0.68
    assert mech.epsilon_at(nm) <= 0.68 + 1e-6


def test_calibrate_higher_epsilon_returns_smaller_noise():
    """A weaker privacy budget (higher ε) needs less noise."""
    weak = DPSGDMechanism(DPConfig(epsilon=10.0, rounds=100))
    strong = DPSGDMechanism(DPConfig(epsilon=0.68, rounds=100))
    assert weak.calibrate() < strong.calibrate()


# ---------------------------------------------------------------- aggregate
def test_aggregate_returns_correct_shape():
    mech = DPSGDMechanism(DPConfig())
    updates = np.zeros((10, 8))
    out = mech.aggregate(updates)
    assert out.shape == (8,)


def test_aggregate_rejects_1d_input():
    mech = DPSGDMechanism(DPConfig())
    with pytest.raises(ValueError):
        mech.aggregate(np.zeros(8))


def test_aggregate_with_all_zero_updates_has_nonzero_noise():
    mech = DPSGDMechanism(DPConfig())
    updates = np.zeros((10, 8))
    out = mech.aggregate(updates)
    # The DP noise means the aggregate is not exactly zero.
    assert np.linalg.norm(out) > 0.0


# ---------------------------------------------------------------- metadata
def test_metadata_reports_thesis_values():
    mech = DPSGDMechanism(DPConfig())
    meta = mech.metadata()
    assert meta["epsilon"] == 0.68
    assert meta["clipping_norm"] == 1.0
    assert meta["rounds"] == 100
    assert "epsilon_at_config" in meta
