"""Unit tests for :mod:`src.models.fl_geometric_median`.

Covers the Byzantine-robust aggregation primitive used by the FL
coordinator (§6.6.4, Eqs. 127–128). The core properties are:

    * the median of a set of identical points is that point,
    * the median is invariant to permutation of the points,
    * the median is not pulled arbitrarily far by a minority of
      outliers (the Byzantine-robust property that motivates the use
      of the geometric median over the arithmetic mean).

The MAD threshold (§6.6.4) is also tested, since it is the mechanism
that isolates Byzantine updates.
"""

from __future__ import annotations

import numpy as np
import pytest

from src.models.fl_geometric_median import (
    clip_by_norm,
    mad_threshold,
    weighted_geometric_median,
)


# ---------------------------------------------------------------- clip
def test_clip_by_norm_does_not_change_small_vectors():
    v = np.array([0.3, 0.4, 0.0])  # norm = 0.5
    out = clip_by_norm(v, C=1.0)
    np.testing.assert_array_equal(out, v)


def test_clip_by_norm_clips_large_vectors():
    v = np.array([3.0, 4.0, 0.0])  # norm = 5
    out = clip_by_norm(v, C=1.0)
    assert np.isclose(np.linalg.norm(out), 1.0)
    # direction preserved
    np.testing.assert_allclose(out / 1.0, v / 5.0)


def test_clip_by_norm_rejects_non_positive_C():
    with pytest.raises(ValueError):
        clip_by_norm(np.zeros(3), C=0.0)
    with pytest.raises(ValueError):
        clip_by_norm(np.zeros(3), C=-1.0)


# ---------------------------------------------------------------- MAD
def test_mad_threshold_returns_finite():
    values = np.array([0.1, 0.2, 0.3, 0.4, 10.0])
    t = mad_threshold(values, sigma=2.5)
    assert np.isfinite(t)
    assert t > np.median(values)


def test_mad_threshold_rejects_empty():
    with pytest.raises(ValueError):
        mad_threshold(np.array([]))


def test_mad_threshold_rejects_non_positive_sigma():
    with pytest.raises(ValueError):
        mad_threshold(np.array([1.0, 2.0]), sigma=0.0)


# ---------------------------------------------------------------- median
def test_geometric_median_of_identical_points():
    points = np.tile(np.array([1.0, 2.0, 3.0]), (10, 1))
    m = weighted_geometric_median(points)
    np.testing.assert_allclose(m, [1.0, 2.0, 3.0], atol=1e-6)


def test_geometric_median_is_permutation_invariant():
    rng = np.random.default_rng(20261130)
    points = rng.normal(0.0, 1.0, size=(20, 4))
    m1 = weighted_geometric_median(points)
    perm = rng.permutation(20)
    m2 = weighted_geometric_median(points[perm])
    np.testing.assert_allclose(m1, m2, atol=1e-6)


def test_geometric_median_of_symmetric_points_is_center():
    """Symmetric points around the origin have median at the origin."""
    pts = np.array([
        [1.0, 0.0],
        [-1.0, 0.0],
        [0.0, 1.0],
        [0.0, -1.0],
    ])
    m = weighted_geometric_median(pts)
    np.testing.assert_allclose(m, [0.0, 0.0], atol=1e-6)


def test_geometric_median_robust_to_outliers():
    """A single far outlier does not pull the median appreciably,
    unlike the arithmetic mean."""
    rng = np.random.default_rng(20261131)
    inliers = rng.normal(0.0, 0.1, size=(20, 4))
    outlier = np.full((1, 4), 100.0)
    points = np.vstack([inliers, outlier])

    median = weighted_geometric_median(points)
    mean = points.mean(axis=0)

    # Median stays near the inlier centre.
    assert np.linalg.norm(median) < 1.0
    # Mean is pulled far away.
    assert np.linalg.norm(mean) > 4.0


def test_geometric_median_with_weights():
    """Weighting the outlier to zero removes its influence."""
    rng = np.random.default_rng(20261132)
    inliers = rng.normal(0.0, 0.1, size=(20, 4))
    outlier = np.full((1, 4), 100.0)
    points = np.vstack([inliers, outlier])
    weights = np.concatenate([np.ones(20), [0.0]])
    m = weighted_geometric_median(points, weights=weights)
    assert np.linalg.norm(m) < 1.0


def test_geometric_median_rejects_empty():
    with pytest.raises(ValueError):
        weighted_geometric_median(np.zeros((0, 4)))


def test_geometric_median_rejects_wrong_weights_shape():
    points = np.zeros((5, 3))
    weights = np.ones(4)
    with pytest.raises(ValueError):
        weighted_geometric_median(points, weights=weights)


def test_geometric_median_rejects_negative_weights():
    points = np.zeros((5, 3))
    weights = np.array([1.0, 1.0, -1.0, 1.0, 1.0])
    with pytest.raises(ValueError):
        weighted_geometric_median(points, weights=weights)


# ---------------------------------------------------------------- determinism
def test_geometric_median_deterministic():
    rng = np.random.default_rng(20261133)
    points = rng.normal(0.0, 1.0, size=(30, 5))
    m1 = weighted_geometric_median(points)
    m2 = weighted_geometric_median(points)
    np.testing.assert_array_equal(m1, m2)
