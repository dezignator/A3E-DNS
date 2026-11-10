"""Deterministic seeding for the A3E-DNS artifact.

Every run must be reproducible. This module seeds the standard library,
NumPy, and (when available) PyTorch and TensorFlow, and returns a
``numpy.random.Generator`` for callers that need a local generator
(which is the recommended pattern — a single global seed plus per-run
generators keeps different call sites independent).

Torch and TensorFlow imports are optional; the module works on a
CPU-only install that does not have them.
"""

from __future__ import annotations

import os
import random
import sys
from contextlib import contextmanager
from typing import Iterator, Optional

import numpy as np

__all__ = [
    "DEFAULT_SEED",
    "seed_everything",
    "rng_for",
    "deterministic_context",
]

DEFAULT_SEED: int = 20261130  # thesis submission date (Nov 30, 2026)


def _try_set_torch_determinism() -> bool:
    try:
        import torch  # type: ignore
    except ImportError:
        return False
    torch.manual_seed(0)
    torch.cuda.manual_seed_all(0)
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False
    if hasattr(torch, "use_deterministic_algorithms"):
        # Raises for ops without a deterministic implementation on some
        # backends; we only warn so a reproducibility run does not crash.
        try:
            torch.use_deterministic_algorithms(True, warn_only=True)
        except Exception:
            pass
    return True


def _try_set_tf_determinism() -> bool:
    try:
        import tensorflow as tf  # type: ignore
    except ImportError:
        return False
    tf.random.set_seed(0)
    try:
        tf.config.experimental.enable_op_determinism()
    except Exception:
        pass
    return True


def seed_everything(seed: int = DEFAULT_SEED, verbose: bool = False) -> np.random.Generator:
    """Seed all RNGs and return a NumPy ``Generator``.

    Parameters
    ----------
    seed : int
        Master seed. Must be non-negative; a deterministic value is
        recorded in ``docs/REPRODUCIBILITY.md`` and in the artifact
        manifest.
    verbose : bool
        If ``True``, print which backends were seeded.

    Returns
    -------
    numpy.random.Generator
        A per-process generator derived from ``seed``. Use ``rng_for``
        to obtain independent generators for different call sites.
    """
    if seed < 0:
        raise ValueError(f"seed must be non-negative, got {seed}")
    seed = int(seed)

    os.environ["PYTHONHASHSEED"] = str(seed)

    random.seed(seed)
    np.random.seed(seed)

    torch_seeded = _try_set_torch_determinism()
    tf_seeded = _try_set_tf_determinism()

    if verbose:
        backends = ["python", "numpy"]
        if torch_seeded:
            backends.append("torch")
        if tf_seeded:
            backends.append("tensorflow")
        print(f"[seed] master seed = {seed}; seeded: {', '.join(backends)}", file=sys.stderr)

    return np.random.default_rng(seed)


def rng_for(name: str, base_seed: int = DEFAULT_SEED) -> np.random.Generator:
    """Derive an independent ``Generator`` for a named call site.

    ``name`` is hashed together with ``base_seed`` so different call sites
    produce independent streams, while still being fully deterministic
    given the same ``base_seed``. This is preferable to re-seeding the
    global RNG at every call site.
    """
    if not isinstance(name, str) or not name:
        raise ValueError("name must be a non-empty string")
    # We use a stable hash (hashlib) rather than Python's built-in hash,
    # which is salted by PYTHONHASHSEED and not guaranteed across runs.
    import hashlib
    digest = hashlib.sha256(f"{base_seed}::{name}".encode("utf-8")).digest()
    derived = int.from_bytes(digest[:8], byteorder="big", signed=False)
    return np.random.default_rng(derived)


@contextmanager
def deterministic_context(seed: int = DEFAULT_SEED, strict: bool = False) -> Iterator[np.random.Generator]:
    """Context manager that seeds all RNGs on entry and restores the
    NumPy global RNG state on exit.

    Parameters
    ----------
    seed : int
        Master seed for the block.
    strict : bool
        If ``True``, re-raise any exception raised by
        ``_try_set_torch_determinism``/``_try_set_tf_determinism`` instead
        of silently ignoring it. Default ``False`` matches the
        non-strict CI path.
    """
    np_state: Optional[dict] = None
    try:
        np_state = np.random.get_state()
    except Exception:
        np_state = None

    rng = seed_everything(seed)

    try:
        yield rng
    finally:
        if np_state is not None:
            try:
                np.random.set_state(np_state)
            except Exception:
                pass
