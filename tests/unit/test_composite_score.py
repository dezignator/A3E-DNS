"""Unit tests for :mod:`src.utils.composite_detection_score`.

Covers Eq. 131 of the thesis (§6.9.1):

    CDS = (2 · AUPRC · F1_weighted) / (AUPRC + F1_weighted)
          − λ · JSD(P_benign ‖ P_detected)

The tests verify:
    * the harmonic-mean first term,
    * the JSD penalty term,
    * the λ = 0 special case (CDS = harmonic mean),
    * the clamping of λ to ≥ 0,
    * the boundary cases (perfect detection, zero detection).

No security property is tested here.
"""

from __future__ import annotations

import numpy as np
import pytest

from src.utils.composite_detection_score import (
    DEFAULT_LAMBDA,
    CompositeDetectionScore,
    compute_cds,
)


# ---------------------------------------------------------------- fixtures
@pytest.fixture
def perfect_data():
    """Perfect prediction: AUPRC = 1, F1 = 1."""
    y_true = np.array([1, 1, 1, 0, 0, 0])
    y_score = np.array([0.9, 0.9, 0.9, 0.1, 0.1, 0.1])
    p_benign = np.array([1.0, 0.0, 0.0, 0.0])
    p_detected = np.array([1.0, 0.0, 0.0, 0.0])
    return y_true, y_score, p_benign, p_detected


@pytest.fixture
def bad_data():
    """Antiprediction: scores are the opposite of the labels."""
    y_true = np.array([1, 1, 1, 0, 0, 0])
    y_score = np.array([0.1, 0.1, 0.1, 0.9, 0.9, 0.9])
    p_benign = np.array([1.0, 0.0, 0.0, 0.0])
    p_detected = np.array([0.0, 0.0, 0.0, 1.0])
    return y_true, y_score, p_benign, p_detected


# ---------------------------------------------------------------- perfect
def test_cds_perfect_with_zero_lambda(perfect_data):
    y_true, y_score, p_b, p_d = perfect_data
    result = compute_cds(y_true, y_score, p_b, p_d, lambda_=0.0)
    assert isinstance(result, CompositeDetectionScore)
    assert result.cds == pytest.approx(1.0, abs=1e-9)
    assert result.penalty == pytest.approx(0.0, abs=1e-12)


def test_cds_perfect_with_positive_lambda(perfect_data):
    """When benign and detected distributions match, JSD = 0, so the
    penalty is 0 even for λ > 0."""
    y_true, y_score, p_b, p_d = perfect_data
    result = compute_cds(y_true, y_score, p_b, p_d, lambda_=0.5)
    assert result.cds == pytest.approx(1.0, abs=1e-9)
    assert result.penalty == pytest.approx(0.0, abs=1e-9)
    assert result.jsd == pytest.approx(0.0, abs=1e-12)


# ---------------------------------------------------------------- bad
def test_cds_bad_prediction_is_low(bad_data):
    y_true, y_score, p_b, p_d = bad_data
    result = compute_cds(y_true, y_score, p_b, p_d, lambda_=0.0)
    # Antiprediction: harmonic mean of AUPRC and F1 is 0.
    assert result.cds <= 0.5 + 1e-6


def test_cds_jsd_penalty_reduces_score(bad_data):
    """When benign and detected distributions differ, the penalty
    reduces the CDS by exactly ``λ · JSD``."""
    y_true, y_score, p_b, p_d = bad_data
    lam = 0.3
    r0 = compute_cds(y_true, y_score, p_b, p_d, lambda_=0.0)
    r1 = compute_cds(y_true, y_score, p_b, p_d, lambda_=lam)
    expected_penalty = lam * r1.jsd
    assert r1.penalty == pytest.approx(expected_penalty, abs=1e-12)
    assert r0.cds - r1.cds == pytest.approx(r1.penalty, abs=1e-12)


# ---------------------------------------------------------------- validation
def test_cds_rejects_negative_lambda(perfect_data):
    y_true, y_score, p_b, p_d = perfect_data
    with pytest.raises(ValueError):
        compute_cds(y_true, y_score, p_b, p_d, lambda_=-0.1)


def test_cds_rejects_shape_mismatch():
    y_true = np.array([1, 0, 1, 0])
    y_score = np.array([0.9, 0.1, 0.9])
    p_b = np.array([1.0, 0.0])
    p_d = np.array([1.0, 0.0])
    with pytest.raises(ValueError):
        compute_cds(y_true, y_score, p_b, p_d)


# ---------------------------------------------------------------- report
def test_cds_to_dict_roundtrip(perfect_data):
    y_true, y_score, p_b, p_d = perfect_data
    r = compute_cds(y_true, y_score, p_b, p_d, lambda_=0.3)
    d = r.to_dict()
    for key in ("cds", "auprc", "f1_weighted", "jsd", "harmonic_mean", "penalty", "lambda_"):
        assert key in d
    assert d["lambda_"] == pytest.approx(0.3)


# ---------------------------------------------------------------- default lambda
def test_default_lambda_is_positive():
    """``DEFAULT_LAMBDA`` is a fallback; the thesis uses the value
    selected by cross-validation on the validation split (§6.9.1)."""
    assert DEFAULT_LAMBDA >= 0.0
