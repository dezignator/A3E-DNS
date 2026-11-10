"""Math primitives used by the SE(3)ⁿ state evolution (§6.4.2).

Provides the so(3) ↔ SO(3) map, the skew-symmetric operator, and the
numerically stable small-angle branches required by the SE(3) exp/log
implementations in ``se3_lie_group``.

Everything here is pure NumPy and operates on the last axis, so the
functions broadcast over arbitrary leading batch dimensions.
"""

from __future__ import annotations

import numpy as np

__all__ = [
    "skew_symmetric",
    "vee",
    "safe_norm",
    "expm_so3",
    "logm_so3",
    "hat_so3",
    "V_matrix",
    "V_inv_matrix",
]


# Small-angle threshold below which the closed-form is replaced by the
# Taylor expansion (1e-8 is safe for float64; the resulting error is
# below machine epsilon for the quantities involved).
_EPS = 1e-8


# ------------------------------------------------------------------ so(3)
def hat_so3(v: np.ndarray) -> np.ndarray:
    """Alias of :func:`skew_symmetric` (operator [v]_×)."""
    return skew_symmetric(v)


def skew_symmetric(v: np.ndarray) -> np.ndarray:
    """Map ``v ∈ R³`` to its skew-symmetric matrix ``[v]_× ∈ so(3)``.

    Supports an arbitrary batch dimension on the leading axes; the last
    axis must have length 3.
    """
    v = np.asarray(v, dtype=np.float64)
    if v.shape[-1] != 3:
        raise ValueError(f"skew_symmetric: last axis must have length 3, got {v.shape[-1]}")
    out = np.zeros(v.shape[:-1] + (3, 3), dtype=np.float64)
    out[..., 0, 1] = -v[..., 2]
    out[..., 0, 2] =  v[..., 1]
    out[..., 1, 0] =  v[..., 2]
    out[..., 1, 2] = -v[..., 0]
    out[..., 2, 0] = -v[..., 1]
    out[..., 2, 1] =  v[..., 0]
    return out


def vee(M: np.ndarray) -> np.ndarray:
    """Map ``M ∈ so(3)`` to ``v ∈ R³`` (inverse of :func:`skew_symmetric`)."""
    M = np.asarray(M, dtype=np.float64)
    if M.shape[-2:] != (3, 3):
        raise ValueError(f"vee: last two axes must be (3, 3), got {M.shape[-2:]}")
    return np.stack([M[..., 2, 1], M[..., 0, 2], M[..., 1, 0]], axis=-1)


def safe_norm(x: np.ndarray, axis: int | None = None, eps: float = _EPS) -> np.ndarray:
    """Euclidean norm that never returns exactly 0 (floor at ``eps``)."""
    n = np.linalg.norm(x, axis=axis, keepdims=(axis is not None))
    return np.maximum(n, eps)


# ---------------------------------------------------------------- SO(3) exp
def expm_so3(omega: np.ndarray) -> np.ndarray:
    """SO(3) exponential map: ``omega ∈ R³ ↦ R ∈ SO(3)`` via Rodrigues.

    For ``||omega|| < 1e-8`` the series ``I + [ω]_× + ½[ω]_×²`` is used;
    this is exact to machine precision on that range and avoids division
    by zero.
    """
    omega = np.asarray(omega, dtype=np.float64)
    if omega.shape[-1] != 3:
        raise ValueError(f"expm_so3: last axis must have length 3, got {omega.shape[-1]}")

    theta = np.linalg.norm(omega, axis=-1, keepdims=True)   # (..., 1)
    K = skew_symmetric(omega)                                # (..., 3, 3)
    K2 = K @ K                                               # (..., 3, 3)
    I = np.eye(3, dtype=np.float64)

    # Branches: small angle vs general.
    small = theta < _EPS
    # Avoid division by zero in the general branch by replacing theta
    # with 1 wherever the branch is small (result is discarded).
    safe_theta = np.where(small, 1.0, theta)

    a = np.where(small, 1.0, np.sin(safe_theta) / safe_theta)            # sin θ / θ
    b = np.where(small, 0.5, (1.0 - np.cos(safe_theta)) / (safe_theta ** 2))  # (1 − cos θ) / θ²

    R = I + a[..., None] * K + b[..., None] * K2
    return R


# ---------------------------------------------------------------- SO(3) log
def logm_so3(R: np.ndarray) -> np.ndarray:
    """SO(3) logarithm: ``R ∈ SO(3) ↦ omega ∈ R³``.

    Uses the quaternion-free closed form with a small-angle branch. The
    rotation matrix is not re-normalised; the caller is responsible for
    passing a valid SO(3) element (the SE(3) driver asserts this).
    """
    R = np.asarray(R, dtype=np.float64)
    if R.shape[-2:] != (3, 3):
        raise ValueError(f"logm_so3: last two axes must be (3, 3), got {R.shape[-2:]}")

    trace = R[..., 0, 0] + R[..., 1, 1] + R[..., 2, 2]
    cos_theta = (trace - 1.0) / 2.0
    cos_theta = np.clip(cos_theta, -1.0, 1.0)
    theta = np.arccos(cos_theta)                             # (...,)
    sin_theta = np.sin(theta)

    vee_R = vee(R - np.swapaxes(R, -1, -2))                  # (..., 3), = 2 sin θ · n

    small = theta < 1e-6
    safe_theta = np.where(small, 1.0, theta)
    safe_sin   = np.where(small, 1.0, sin_theta)

    # General branch: ω = θ / (2 sin θ) · vee(R − Rᵀ)
    factor = np.where(small, 0.5, safe_theta / (2.0 * safe_sin))
    omega = factor[..., None] * vee_R

    # Near θ = π the closed form is ill-conditioned; fall back to the
    # matrix logarithm via eigendecomposition (rare, but must not crash).
    near_pi = theta > np.pi - 1e-6
    if np.any(near_pi):
        omega = _logm_so3_near_pi(R, omega, near_pi)
    return omega


def _logm_so3_near_pi(R: np.ndarray, omega: np.ndarray, mask: np.ndarray) -> np.ndarray:
    """Robust SO(3) log for rotations close to a half-turn."""
    omega = np.array(omega, copy=True)
    flat = R.reshape(-1, 3, 3)
    flat_omega = omega.reshape(-1, 3)
    flat_mask = mask.reshape(-1)
    for idx in np.nonzero(flat_mask)[0]:
        w, V = np.linalg.eig(flat[idx])
        axis = np.real(V[:, np.argmin(np.abs(w - 1.0))])
        n = axis / (np.linalg.norm(axis) + 1e-15)
        flat_omega[idx] = n * np.pi
    return flat_omega.reshape(omega.shape)


# ---------------------------------------------------------------- se(3) V
def V_matrix(omega: np.ndarray) -> np.ndarray:
    """Left Jacobian ``V(ω) ∈ R^{3×3}`` of SO(3).

    ``V(ω) = I + (1 − cos θ)/θ² · [ω]_× + (θ − sin θ)/θ³ · [ω]_×²``
    """
    omega = np.asarray(omega, dtype=np.float64)
    theta = np.linalg.norm(omega, axis=-1, keepdims=True)
    K = skew_symmetric(omega)
    K2 = K @ K
    I = np.eye(3, dtype=np.float64)

    small = theta < _EPS
    safe_theta = np.where(small, 1.0, theta)

    a = np.where(small, 0.5,   (1.0 - np.cos(safe_theta)) / (safe_theta ** 2))
    b = np.where(small, 1.0 / 6.0, (safe_theta - np.sin(safe_theta)) / (safe_theta ** 3))

    return I + a[..., None] * K + b[..., None] * K2


def V_inv_matrix(omega: np.ndarray) -> np.ndarray:
    """Inverse of :func:`V_matrix`, the SO(3) inverse-left Jacobian.

    ``V⁻¹(ω) = I − ½[ω]_× + (1/θ²)(1 − (θ sin θ) / (2(1 − cos θ))) [ω]_×²``
    """
    omega = np.asarray(omega, dtype=np.float64)
    theta = np.linalg.norm(omega, axis=-1, keepdims=True)
    K = skew_symmetric(omega)
    K2 = K @ K
    I = np.eye(3, dtype=np.float64)

    small = theta < _EPS
    safe_theta = np.where(small, 1.0, theta)
    cos_t = np.cos(safe_theta)
    sin_t = np.sin(safe_theta)

    # coefficient of K²:
    #   general: (1/θ²) · (1 − θ sin θ / (2(1 − cos θ)))
    #   small  : 1/12
    general = (1.0 / (safe_theta ** 2)) * (1.0 - (safe_theta * sin_t) / (2.0 * (1.0 - cos_t)))
    c = np.where(small, 1.0 / 12.0, general)

    return I - 0.5 * K + c[..., None] * K2
