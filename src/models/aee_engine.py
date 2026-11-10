"""Adaptive Evolutionary Encryption engine — thesis §6.4, Eqs. 119–122.

The engine evolves an encryption state ``E(t)`` on the ``SE(3)ⁿ`` group
using a stochastic differential equation (§6.4.1):

    dE(t)/dt = F(E(t), T(t), A(t)) + σ(t) dW_t          (Eq. 119)

where:

    * ``F(·)`` is the deterministic adaptation term driven by traffic
      ``T(t)`` and threat ``A(t)``; it is realised by the lightweight
      neural controller of §6.4.5.
    * ``σ(t) dW_t`` is the stochastic term; ``σ(t)`` is derived from the
      Kullback–Leibler divergence between the observed traffic and a
      learned baseline (§6.4.3, Eq. 120):

            σ(t) = Ψ(D_KL(P_traffic ‖ P_baseline))

The state is discretised as described in §6.4.2:

    * the rotational component of the Lie-algebra update produces the
      **256-bit session key** via quantisation + key-derivation function;
    * the translational component produces the **IV** and the **rotation
      cadence**.

The engine is a **heuristic construction**: it is not claimed to be
IND-CCA2 by itself. The formal security argument is reserved for the
key-encapsulation layer (Proposition 1, §5.2.6). The diffusion
coefficient is kept strictly positive (``σ_min > 0``), matching the
thesis's statement that the diffusion is "bounded away from zero" and
deliberately not annealed as ``t`` grows (Eq. 122, §6.4.4).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from src.utils.se3_lie_group import (
    se3n_compose,
    se3n_exp,
    se3n_identity,
    se3n_log,
    se3n_project,
)
from src.utils.seed import DEFAULT_SEED, rng_for

__all__ = [
    "AEEState",
    "AEEEngineConfig",
    "AEEEngine",
    "kdf_256",
    "derive_iv_and_cadence",
]


# --------------------------------------------------------------- KDF helpers
def kdf_256(material: bytes, *, context: bytes = b"a3e-dns/aee/v1") -> bytes:
    """Derive a 256-bit (32-byte) key from ``material`` via SHA-256.

    The ``context`` is prepended to bind the key to the framework and
    version. This is a standard key-derivation function application; the
    thesis does not propose a new KDF.
    """
    if not isinstance(material, (bytes, bytearray)):
        raise TypeError("material must be bytes")
    h = hashlib.sha256()
    h.update(context)
    h.update(b"\x00")
    h.update(bytes(material))
    return h.digest()


def derive_iv_and_cadence(
    translation: np.ndarray,
    *,
    iv_bits: int = 96,
    cadence_seconds_range: tuple[float, float] = (5.0, 60.0),
) -> tuple[bytes, float]:
    """Derive the IV and the key-rotation cadence from the translational block.

    The thesis (§6.4.2) assigns the translational block the role of
    "initialization vector and the rotation cadence". The mapping here is:

    * IV: hash the flattened translation and take ``iv_bits`` bits;
    * cadence: linearly map the L2 norm of the translation, clipped to a
      stable range, onto ``cadence_seconds_range``.

    The exact numerical mapping is an implementation choice; it does not
    affect the security argument, which is reserved for the KEM layer.
    """
    translation = np.asarray(translation, dtype=np.float64).ravel()
    if translation.size == 0:
        raise ValueError("translation must be non-empty")

    iv_bytes = kdf_256(translation.tobytes(), context=b"a3e-dns/aee/iv/v1")[
        : max(1, iv_bits // 8)
    ]

    norm = float(np.linalg.norm(translation))
    lo, hi = cadence_seconds_range
    # A monotone squash: [0, ∞) → [lo, hi). The exact shape is not part of
    # the thesis claim; only that the cadence is derived from the
    # translation and stays inside a bounded range.
    cadence = lo + (hi - lo) * (norm / (1.0 + norm))
    return iv_bytes, float(cadence)


# --------------------------------------------------------------- config
@dataclass(frozen=True)
class AEEEngineConfig:
    """Configuration for :class:`AEEEngine`.

    Attributes
    ----------
    se3_dim : int
        Number of ``SE(3)`` factors (``n`` in ``SE(3)ⁿ``).
    key_bits : int
        Session-key length in bits. Must be 256.
    state_vector_dim : int
        Quantisation width per component (thesis: 64, quantised at 16 bits).
    sigma_min : float
        Strict lower bound on the diffusion coefficient. Must be > 0.
    sigma_max : float
        Strict upper bound. Must be > ``sigma_min``.
    dt : float
        Time step for the Euler–Maruyama update.
    iv_bits : int
        Length of the derived IV, in bits.
    cadence_seconds_range : tuple[float, float]
        Allowed range of the derived rotation cadence.
    seed : int
        Master seed for the deterministic noise source.
    rng_name : str
        Name used to derive an independent RNG (``src.utils.seed.rng_for``).
    """

    se3_dim: int = 1
    key_bits: int = 256
    state_vector_dim: int = 64
    sigma_min: float = 1.0e-6
    sigma_max: float = 1.0e-2
    dt: float = 1.0
    iv_bits: int = 96
    cadence_seconds_range: tuple[float, float] = (5.0, 60.0)
    seed: int = DEFAULT_SEED
    rng_name: str = "aee_engine"

    def __post_init__(self) -> None:
        if self.se3_dim < 1:
            raise ValueError(f"se3_dim must be ≥ 1, got {self.se3_dim}")
        if self.key_bits != 256:
            raise ValueError(f"key_bits must be 256, got {self.key_bits}")
        if self.state_vector_dim < 1:
            raise ValueError(f"state_vector_dim must be ≥ 1, got {self.state_vector_dim}")
        if not (0.0 < self.sigma_min < self.sigma_max):
            raise ValueError(
                f"require 0 < sigma_min < sigma_max, got "
                f"sigma_min={self.sigma_min}, sigma_max={self.sigma_max}"
            )
        if self.dt <= 0.0:
            raise ValueError(f"dt must be > 0, got {self.dt}")
        if self.iv_bits <= 0 or self.iv_bits % 8 != 0:
            raise ValueError(f"iv_bits must be a positive multiple of 8, got {self.iv_bits}")
        lo, hi = self.cadence_seconds_range
        if not (0.0 < lo < hi):
            raise ValueError(
                f"cadence_seconds_range must satisfy 0 < lo < hi, got {self.cadence_seconds_range}"
            )


# --------------------------------------------------------------- state
@dataclass
class AEEState:
    """Live state of the AEE engine.

    Attributes
    ----------
    R : np.ndarray, shape (n, 3, 3)
        Rotational component of ``SE(3)ⁿ``.
    t : np.ndarray, shape (n, 3)
        Translational component of ``SE(3)ⁿ``.
    session_key : bytes
        256-bit session key (32 bytes), derived from the rotational block.
    iv : bytes
        Initialisation vector, derived from the translational block.
    rotation_cadence_seconds : float
        Current rotation cadence, derived from the translational block.
    step : int
        Number of discrete updates applied so far.
    entropy_trace : tuple[float, ...]
        Recorded ``D_KL`` values, used for the reproducibility manifest.
    """

    R: np.ndarray
    t: np.ndarray
    session_key: bytes
    iv: bytes
    rotation_cadence_seconds: float
    step: int = 0
    entropy_trace: tuple[float, ...] = field(default_factory=tuple)

    def to_dict(self, include_secrets: bool = False) -> dict[str, Any]:
        """Serialise the state for logging/manifest.

        Session key and IV are redacted unless ``include_secrets=True``.
        """
        return {
            "R_shape": list(self.R.shape),
            "t_shape": list(self.t.shape),
            "session_key": self.session_key.hex() if include_secrets else "<redacted>",
            "iv": self.iv.hex() if include_secrets else "<redacted>",
            "rotation_cadence_seconds": self.rotation_cadence_seconds,
            "step": self.step,
            "entropy_trace": list(self.entropy_trace),
        }


# --------------------------------------------------------------- engine
class AEEEngine:
    """Discrete-time AEE engine.

    Parameters
    ----------
    config : AEEEngineConfig
        Engine configuration.
    controller : callable, optional
        The neural controller from §6.4.5. It must have the signature
        ``controller(features) -> xi`` where ``xi`` is an ``(n, 6)`` array
        of Lie-algebra increments. If ``None``, the engine uses a small
        deterministic zero-order fallback that produces the identity
        increment. This keeps the engine runnable in isolation for tests
        and toy mode.

    Notes
    -----
    * The engine is **not** a security module. The formal security
      argument in the thesis is reserved for the KEM layer
      (Proposition 1, §5.2.6).
    * The diffusion coefficient is bounded strictly away from zero
      (``sigma_min > 0``), matching §6.4.4.
    """

    def __init__(
        self,
        config: AEEEngineConfig | None = None,
        *,
        controller: callable | None = None,
    ) -> None:
        self.config = config or AEEEngineConfig()
        self._controller = controller
        self._rng = rng_for(self.config.rng_name, base_seed=self.config.seed)
        self._state: AEEState | None = None

    # --------------------------------------------------------------- init
    def initialize(self) -> AEEState:
        """Initialise the state at the identity of ``SE(3)ⁿ``."""
        R, t = se3n_identity(self.config.se3_dim)
        session_key = self._derive_session_key(R, t)
        iv, cadence = derive_iv_and_cadence(
            t.ravel(),
            iv_bits=self.config.iv_bits,
            cadence_seconds_range=self.config.cadence_seconds_range,
        )
        self._state = AEEState(
            R=R,
            t=t,
            session_key=session_key,
            iv=iv,
            rotation_cadence_seconds=cadence,
            step=0,
            entropy_trace=(),
        )
        return self._state

    # --------------------------------------------------------------- step
    def step(
        self,
        features: np.ndarray,
        *,
        kl_divergence: float,
    ) -> AEEState:
        """Advance the state by one Euler–Maruyama step.

        Parameters
        ----------
        features : np.ndarray
            Feature vector(s) from the last window. The array is passed
            unchanged to the controller, which is responsible for its own
            shape contract.
        kl_divergence : float
            ``D_KL(P_traffic ‖ P_baseline)`` for the current window. Must
            be ≥ 0.

        Returns
        -------
        AEEState
            The updated state. The previous state is not mutated; the
            engine keeps the latest one.
        """
        if self._state is None:
            self.initialize()
        assert self._state is not None  # for type checkers

        if kl_divergence < 0.0:
            raise ValueError(f"kl_divergence must be ≥ 0, got {kl_divergence}")

        # Deterministic adaptation term F(·) via the neural controller.
        if self._controller is not None:
            xi_det = np.asarray(self._controller(features), dtype=np.float64)
            if xi_det.shape != (self.config.se3_dim, 6):
                raise ValueError(
                    f"controller returned shape {xi_det.shape}, "
                    f"expected ({self.config.se3_dim}, 6)"
                )
            xi_det = se3n_project(xi_det)
        else:
            xi_det = np.zeros((self.config.se3_dim, 6), dtype=np.float64)

        # Stochastic term σ(t) · dW_t. σ(t) is bounded strictly away from
        # zero, matching Eq. 122 and the §6.4.4 design choice.
        sigma = self._sigma(kl_divergence)
        dW = self._rng.normal(0.0, np.sqrt(self.config.dt), size=(self.config.se3_dim, 6))
        xi_stoch = sigma * dW

        # Euler–Maruyama on the group: K_{t+1} = K_t · exp(ξ_t dt + Σ dW_t)
        xi_total = (xi_det + xi_stoch) * self.config.dt

        R_next, t_next = se3n_exp(xi_total)
        R_curr, t_curr = self._state.R, self._state.t
        R_new, t_new = se3n_compose(R_curr, t_curr, R_next, t_next)

        session_key = self._derive_session_key(R_new, t_new)
        iv, cadence = derive_iv_and_cadence(
            t_new.ravel(),
            iv_bits=self.config.iv_bits,
            cadence_seconds_range=self.config.cadence_seconds_range,
        )

        self._state = AEEState(
            R=R_new,
            t=t_new,
            session_key=session_key,
            iv=iv,
            rotation_cadence_seconds=cadence,
            step=self._state.step + 1,
            entropy_trace=self._state.entropy_trace + (float(kl_divergence),),
        )
        return self._state

    # --------------------------------------------------------------- accessors
    @property
    def state(self) -> AEEState:
        """Return the current state; raise if :meth:`initialize` has not been called."""
        if self._state is None:
            raise RuntimeError("AEEEngine.initialize() has not been called")
        return self._state

    # --------------------------------------------------------------- internals
    def _sigma(self, kl_divergence: float) -> float:
        """Map ``D_KL`` onto the closed interval [σ_min, σ_max].

        The thesis requires ``σ(t)`` to be bounded strictly away from zero
        (§6.4.4, Eq. 122). We use a monotone squash that saturates at
        ``σ_max`` for large divergences, so the lower bound ``σ_min`` is
        never violated regardless of the input.
        """
        lo, hi = self.config.sigma_min, self.config.sigma_max
        # A monotone map [0, ∞) → [lo, hi) with a smooth approach to hi.
        d = max(0.0, float(kl_divergence))
        return float(lo + (hi - lo) * (d / (1.0 + d)))

    def _derive_session_key(self, R: np.ndarray, t: np.ndarray) -> bytes:
        """Quantise the Lie-group state and derive the 256-bit key.

        The thesis (§6.4.2) assigns the rotational block the role of key
        material. We hash the full state (rotation + translation) so that
        translation-dependent IVs and cadences are bound to the same
        quantised blob; the caller is free to re-derive a key from the
        rotation alone if a stricter separation is required. The 256-bit
        output is the value used by the session.
        """
        # Quantise to 16 bits per component, per §6.4.1 / §6.4.2.
        q_R = np.round(R * 32767.0).astype(np.int32).tobytes()
        q_t = np.round(t * 32767.0).astype(np.int32).tobytes()
        material = q_R + b"|" + q_t
        return kdf_256(material, context=b"a3e-dns/aee/session/v1")

    # --------------------------------------------------------------- helpers
    def rollback(self) -> AEEState:
        """Reset to the identity state.

        Useful for failover (Table 27: ``aee-fallback``). Keeps the
        controller and the RNG; only the state is reset.
        """
        return self.initialize()
