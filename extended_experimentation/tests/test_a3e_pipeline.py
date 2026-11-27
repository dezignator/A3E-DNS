#!/usr/bin/env python3
"""Smoke tests for the A3E-DNS runtime pipeline."""
from pathlib import Path
import numpy as np
import pytest

from extended_experimentation.deployment.a3e_pipeline import (
    A3EPipeline, Decision, Detector, PipelineConfig, run_smoke,
)


def test_detector_returns_decision_and_probability():
    detector = Detector(None)
    features = np.zeros(16)
    decision, prob = detector.classify(features)
    assert decision in (Decision.BENIGN, Decision.ATTACK)
    assert 0.0 <= prob <= 1.0


def test_pipeline_rejects_wrong_feature_shape():
    detector = Detector(None)
    pipeline = A3EPipeline(
        config=PipelineConfig(enable_attestation=False, enable_aee=False),
        detector=detector,
    )
    with pytest.raises(ValueError):
        pipeline.classify(np.zeros(15))


def test_pipeline_smoke_records_latency():
    stats = run_smoke(
        PipelineConfig(enable_attestation=False, enable_aee=False),
        n_queries=500,
        seed=20231130,
    )
    assert stats["n_queries"] == 500
    assert stats["latency_ms"]["median"] >= 0.0
    assert 0.0 <= stats["violation_rate"] <= 1.0


def test_pipeline_throughput_estimate_positive():
    stats = run_smoke(
        PipelineConfig(enable_attestation=False, enable_aee=False),
        n_queries=200,
    )
    assert stats["throughput_qps_estimate"] > 0.0
