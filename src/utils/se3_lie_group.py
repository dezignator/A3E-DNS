"""SE(3)ⁿ Lie-group utilities (§6.4.2).

Implements the SE(3) exp/log map, the Lie-algebra projection ``Π_g``
used by the Adaptive Evolutionary Encryption engine (§3.10.2, Eq. 26),
and the batched forms required by the ``K_{t+1} = K_t · exp(ξ_t Δt + Σ ΔW)``
recurrence.

Notation. An SE(3) element is a pair ``(R, t)`` with ``R ∈ SO(3)``,
``t ∈ R³``. A tangent vector (Lie algebra ``se(3)``) is a pair
``(ω, v)`` with ``ω ∈ R³`` (so(3) in vector form) and ``v ∈ R³``.

All functions broadcast over leading batch dimensions; the last axis
must have length 3 for the vector form and (3, 3) / (3,) for the matrix
form. ``SE3ⁿ`` is handled by the ``se3n_*`` helpers, which treat the
leading axis as the product index.
"""

from __future__ import annotations

import numpy as np

from src.utils.math_utils import (
    skew_symmetric,
    vee,
    expm_so3,
    logm_so3,
    V_matrix,
    V_inv_matrix,
)

__all__ = [
    "se3_exp",
    "se3_log",
    "se3_compose",
    "se3_inverse",
    "project_se3",
    "project_so3_matrix",
    "se3n_exp",
    "se3n_log",
    "se3n_compose",
    "se3n_inverse",
    "se3n_project",
    "se3n_random",
    "se3n_identity",
]


# ---------------------------------------------------------------- se(3) exp
def se3_exp(omega: np.ndarray, v: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """SE(3) exponential map: ``(ω, v) ∈ se(3) ↦ (R, t) ∈ SE(3)``.

    ``R = exp_{SO(3)}(ω)``, ``t = V(ω) · v`` with ``V`` the SO(3) left
    Jacobian. Supports arbitrary leading batch dimensions.
    """
    omega = np.asarray(omega, dtype=np.float64)
    v = np.asarray(v, dtype=np.float64)
    if omega.shape[-1] != 3 or v.shape[-1] != 3:
        raise ValueError("se3_exp: omega and v must have shape (..., 3)")

    R = expm_so3(omega)
    V = V_matrix(omega)
    t = np.einsum("...ij,...j->...i", V, v)
    return R, t


def se3_log(R: np.ndarray, t: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """SE(3) logarithm: ``(R, t) ∈ SE(3) ↦ (ω, v) ∈ se(3)``."""
    R = np.asarray(R, dtype=np.float64)
    t = np.asarray(t, dtype=np.float64)
    if R.shape[-2:] != (3, 3) or t.shape[-1] != 3:
        raise ValueError("se3_log: R must have shape (..., 3, 3) and t (..., 3)")

    omega = logm_so3(R)
    V_inv = V_inv_matrix(omega)
    v = np.einsum("...ij,...j->...i", V_inv, t)
    return omega, v


# ---------------------------------------------------------------- group ops
def se3_compose(
    R1: np.ndarray, t1: np.ndarray,
    R2: np.ndarray, t2: np.ndarray,
) -> tuple[np.ndarray, np.ndarray]:
    """Compose two SE(3) elements: ``(R1·R2, R1·t2 + t1)``."""
    R1 = np.asarray(R1, dtype=np.float64)
    R2 = np.asarray(R2, dtype=np.float64)
    t1 = np.asarray(t1, dtype=np.float64)
    t2 = np.asarray(t2, dtype=np.float64)
    R = R1 @ R2
    t = np.einsum("...ij,...j->...i", R1, t2) + t1
    return R, t


def se3_inverse(R: np.ndarray, t: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """SE(3) inverse: ``(Rᵀ, −Rᵀ·t)``."""
    R = np.asarray(R, dtype=np.float64)
    t = np.asarray(t, dtype=np.float64)
    Rt = np.swapaxes(R, -1, -2)
    t_inv = -np.einsum("...ij,...j->...i", Rt, t)
    return Rt, t_inv


# ---------------------------------------------------------------- projection
def project_so3_matrix(M: np.ndarray) -> np.ndarray:
    """Skew-symmetrise a 3×3 matrix: ``Π_{so(3)}(M) = (M − Mᵀ) / 2``.

    Used by the AEE engine to project the neural controller's output
    onto the Lie algebra (§3.10.2: "the projection Π_g was implemented as
    the skew-symmetrization of the rotational block").
    """
    M = np.asarray(M, dtype=np.float64)
    if M.shape[-2:] != (3, 3):
        raise ValueError(f"project_so3_matrix: last two axes must be (3, 3), got {M.shape[-2:]}")
    return 0.5 * (M - np.swapaxes(M, -1, -2))


def project_se3(omega: np.ndarray, v: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Project ``(ω, v)`` onto se(3).

    Because ``ω`` is already a 3-vector (so(3) in vector form via the hat
    map), the projection is the identity on ``ω``; the ``v`` component is
    unconstrained. Provided for API symmetry with :func:`se3_exp`.
    """
    omega = np.asarray(omega, dtype=np.float64)
    v = np.asarray(v, dtype=np.float64)
    if omega.shape[-1] != 3 or v.shape[-1] != 3:
        raise ValueError("project_se3: omega and v must have shape (..., 3)")
    return omega.copy(), v.copy()


# ---------------------------------------------------------------- SE(3)ⁿ
def se3n_identity(n: int) -> tuple[np.ndarray, np.ndarray]:
    """Identity element of SE(3)ⁿ: ``(I₃, 0)`` repeated ``n`` times."""
    if n < 1:
        raise ValueError(f"se3n_identity: n must be ≥ 1, got {n}")
    R = np.broadcast_to(np.eye(3, dtype=np.float64), (n, 3, 3)).copy()
    t = np.zeros((n, 3), dtype=np.float64)
    return R, t


def se3n_exp(xi: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Batched SE(3)ⁿ exponential.

    Parameters
    ----------
    xi : array, shape ``(n, 6)``
        Tangent vector for each of the ``n`` product components, with
        ``xi[i, :3] = ω_i`` and ``xi[i, 3:] = v_i``.

    Returns
    -------
    (R, t) with shapes ``(n, 3, 3)`` and ``(n, 3)``.
    """
    xi = np.asarray(xi, dtype=np.float64)
    if xi.ndim != 2 or xi.shape[1] != 6:
        raise ValueError(f"se3n_exp: xi must have shape (n, 6), got {xi.shape}")
    return se3_exp(xi[:, :3], xi[:, 3:])


def se3n_log(R: np.ndarray, t: np.ndarray) -> np.ndarray:
    """Batched SE(3)ⁿ logarithm. Returns ``xi`` of shape ``(n, 6)``."""
    omega, v = se3_log(R, t)
    return np.concatenate([omega, v], axis=-1)


def se3n_compose(
    R1: np.ndarray, t1: np.ndarray,
    R2: np.ndarray, t2: np.ndarray,
) -> tuple[np.ndarray, np.ndarray]:
    """Component-wise composition of two SE(3)ⁿ elements."""
    return se3_compose(R1, t1, R2, t2)


def se3n_inverse(R: np.ndarray, t: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Component-wise inverse of an SE(3)ⁿ element."""
    return se3_inverse(R, t)


def se3n_project(xi: np.ndarray) -> np.ndarray:
    """Project an ``(n, 6)`` array onto ``se(3)ⁿ``.

    For vector-form input this is the identity; the function is provided
    as the named entry point for the ``Π_g`` projection used in the AEE
    engine, so that callers do not need to remember the representation.
    """
    xi = np.asarray(xi, dtype=np.float64)
    if xi.ndim != 2 or xi.shape[1] != 6:
        raise ValueError(f"se3n_project: xi must have shape (n, 6), got {xi.shape}")
    return xi.copy()


def se3n_random(
    rng: np.random.Generator,
    n: int,
    omega_scale: float = 0.1,
    v_scale: float = 0.1,
) -> tuple[np.ndarray, np.ndarray]:
    """Draw a random SE(3)ⁿ element from a Gaussian tangent distribution.

    Parameters
    ----------
    rng : numpy.random.Generator
        Source of randomness. Determinism is the caller's responsibility
        (see ``src.utils.seed``).
    n : int
        Number of product components.
    omega_scale, v_scale : float
        Standard deviations of the Gaussian tangent components.
    """
    if n < 1:
        raise ValueError(f"se3n_random: n must be ≥ 1, got {n}")
    omega = rng.normal(0.0, omega_scale, size=(n, 3))
    v = rng.normal(0.0, v_scale, size=(n, 3))
    return se3_exp(omega, v)
