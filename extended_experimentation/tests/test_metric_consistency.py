#!/usr/bin/env python3
"""Assertions on the metric tolerance bands across modules."""
from extended_experimentation.attack_scenarios.a3e_attack_catalogue import (
    THESIS_REFERENCE as CATALOGUE_REF,
)
from extended_experimentation.evaluation.a3e_evaluation_suite import (
    THESIS_REFERENCE as EVAL_REF,
    TOLERANCES,
)


def test_thesis_references_are_identical():
    # Every module that carries a thesis reference should agree.
    for key in CATALOGUE_REF:
        assert EVAL_REF[key] == CATALOGUE_REF[key], key


def test_tolerance_bands_contain_reference():
    for metric, (lo, hi) in TOLERANCES.items():
        assert lo <= EVAL_REF[metric] <= hi, metric


def test_tolerance_bands_are_ordered():
    for metric, (lo, hi) in TOLERANCES.items():
        assert lo < hi, metric
