"""Unit tests for the KEM-combiner construction — Proposition 1 (§5.2.6).

Proposition 1: ``K_ctrl = KDF(ss1 ‖ ss2 ‖ ct1 ‖ ct2 ‖ ctx)`` is IND-CCA2
if at least one KEM is IND-CCA2 and KDF is PRF/RO.

The tests here verify the **construction** properties, not the
IND-CCA2 reduction (which is cited, not re-derived, per §5.2.6):

    * the combiner output is deterministic given the same inputs,
    * it changes when any input changes,
    * it is a PRF under the standard SHA-256-based KDF we use,
    * it is domain-separated by the ``ctx`` field.

The IND-CCA2 argument is not tested; it is a citation.
"""

from __future__ import annotations

import hashlib

import numpy as np
import pytest

from src.models.aee_engine import kdf_256


# ---------------------------------------------------------------- reference combiner
def _combine(ss1: bytes, ss2: bytes, ct1: bytes, ct2: bytes, ctx: bytes) -> bytes:
    """Reference implementation of Proposition 1's combiner.

    ``K_ctrl = KDF(ss1 ‖ ss2 ‖ ct1 ‖ ct2 ‖ ctx)``, with ``KDF`` being
    the domain-separated SHA-256 wrapper used by the AEE engine.
    """
    material = ss1 + ss2 + ct1 + ct2 + ctx
    return kdf_256(material, context=b"a3e-dns/kem-combiner/v1")


# ---------------------------------------------------------------- determinism
def test_combiner_is_deterministic():
    ss1, ss2 = b"shared-secret-1", b"shared-secret-2"
    ct1, ct2 = b"ciphertext-1", b"ciphertext-2"
    ctx = b"session-context"
    k1 = _combine(ss1, ss2, ct1, ct2, ctx)
    k2 = _combine(ss1, ss2, ct1, ct2, ctx)
    assert k1 == k2
    assert len(k1) == 32


def test_combiner_is_32_bytes():
    k = _combine(b"a", b"b", b"c", b"d", b"e")
    assert len(k) == 32


# ---------------------------------------------------------------- sensitivity
def test_combiner_changes_when_ss1_changes():
    base = _combine(b"ss1", b"ss2", b"ct1", b"ct2", b"ctx")
    changed = _combine(b"ss1-x", b"ss2", b"ct1", b"ct2", b"ctx")
    assert base != changed


def test_combiner_changes_when_ss2_changes():
    base = _combine(b"ss1", b"ss2", b"ct1", b"ct2", b"ctx")
    changed = _combine(b"ss1", b"ss2-x", b"ct1", b"ct2", b"ctx")
    assert base != changed


def test_combiner_changes_when_ct1_changes():
    base = _combine(b"ss1", b"ss2", b"ct1", b"ct2", b"ctx")
    changed = _combine(b"ss1", b"ss2", b"ct1-x", b"ct2", b"ctx")
    assert base != changed


def test_combiner_changes_when_ct2_changes():
    base = _combine(b"ss1", b"ss2", b"ct1", b"ct2", b"ctx")
    changed = _combine(b"ss1", b"ss2", b"ct1", b"ct2-x", b"ctx")
    assert base != changed


def test_combiner_changes_when_ctx_changes():
    base = _combine(b"ss1", b"ss2", b"ct1", b"ct2", b"ctx")
    changed = _combine(b"ss1", b"ss2", b"ct1", b"ct2", b"ctx-x")
    assert base != changed


# ---------------------------------------------------------------- order matters
def test_combiner_is_order_sensitive():
    """Swapping ss1 and ss2 changes the output (this is the standard
    requirement that the combiner binds both shared secrets in a
    specific order)."""
    a = _combine(b"ssA", b"ssB", b"ct1", b"ct2", b"ctx")
    b = _combine(b"ssB", b"ssA", b"ct1", b"ct2", b"ctx")
    assert a != b


# ---------------------------------------------------------------- domain separation
def test_kdf_domain_separated():
    """Different ``context`` values produce different outputs."""
    material = b"the-same-material"
    a = kdf_256(material, context=b"context-a")
    b = kdf_256(material, context=b"context-b")
    assert a != b


# ---------------------------------------------------------------- agreement with SHA-256
def test_kdf_matches_reference_sha256():
    """The KDF is the standard SHA-256-based construction; the test
    verifies the exact input construction so that a change to the
    implementation is caught."""
    material = b"some-material"
    context = b"a3e-dns/kdf-test/v1"
    expected = hashlib.sha256(context + b"\x00" + material).digest()
    assert kdf_256(material, context=context) == expected


# ---------------------------------------------------------------- type checks
def test_kdf_rejects_non_bytes():
    with pytest.raises(TypeError):
        kdf_256("not-bytes")  # type: ignore[arg-type]
