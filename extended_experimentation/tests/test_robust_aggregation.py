#!/usr/bin/env python3
"""Assertions on the robust aggregation primitives."""
import numpy as np

from extended_experimentation.fl.federated_defense_trainer import (
    Aggregator, aggregate_updates,
)


def _make_updates(n: int, dim: int = 4, seed: int = 0):
    rng = np.random.default_rng(seed)
    return [[rng.normal(0.0, 0.1, size=dim)] for _ in range(n)]


def test_mean_aggregator_equals_average():
    updates = _make_updates(5)
    agg = aggregate_updates(updates, Aggregator.MEAN)
    expected = np.stack([u[0] for u in updates], axis=0).mean(axis=0)
    assert np.allclose(agg[0], expected)


def test_median_aggregator_ignores_single_outlier():
    updates = _make_updates(5)
    outlier = [np.array([100.0, 100.0, 100.0, 100.0])]
    updates_with_outlier = updates + [outlier]
    agg_clean = aggregate_updates(updates, Aggregator.MEDIAN)[0]
    agg_noisy = aggregate_updates(updates_with_outlier, Aggregator.MEDIAN)[0]
    # Median should tolerate one outlier in six updates better than mean.
    mean_clean = aggregate_updates(updates, Aggregator.MEAN)[0]
    mean_noisy = aggregate_updates(updates_with_outlier, Aggregator.MEAN)[0]
    assert np.linalg.norm(agg_noisy - agg_clean) < np.linalg.norm(mean_noisy - mean_clean)


def test_trimmed_mean_requires_byzantine_fraction():
    updates = _make_updates(10)
    agg = aggregate_updates(
        updates, Aggregator.TRIMMED_MEAN, byzantine_fraction=0.2
    )
    assert agg[0].shape == (4,)


def test_krum_returns_one_of_the_updates():
    updates = _make_updates(7)
    agg = aggregate_updates(updates, Aggregator.KRUM, byzantine_fraction=0.1)
    # Krum selects an existing update, so its norm must match one of them.
    norms = [np.linalg.norm(u[0]) for u in updates]
    assert any(abs(np.linalg.norm(agg[0]) - n) < 1e-9 for n in norms)
