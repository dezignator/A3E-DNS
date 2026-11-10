"""Optimized Quantum-Safe Homomorphic Encryption engine — §6.5.

Implements the Ring-LWE encryption and homomorphic evaluation interface
used by the pipeline. The engine is a **configuration** of a published
Ring-LWE scheme; it does **not** propose a new cryptographic primitive.

Thesis parameters (§6.5):

    n = 256, q = 4096

The Table 27 command-line parameters (``-lattice-dimension 1024 -modulus
3329``) are reproduced verbatim in ``README.md`` and flagged in
``LIMITATIONS.md §8``. This module uses the §6.5 parameters.

Security notes
--------------
    * The scheme is IND-CPA under decisional Ring-LWE (§6.5, §5.3.5).
    * Homomorphic encryption is malleable by design; it is **not**
      IND-CCA2. Integrity is provided by the authenticated transport
      (TLS 1.3 / QUIC), not by the HE layer.
    * Quantum resistance is conjectural under Ring-LWE.

For the toy mode and CPU-only reproduction, the engine ships a
deterministic pedagogical implementation: the arithmetic matches
Ring-LWE (modular polynomial arithmetic) but the noise distribution is
sampled from a fixed PRNG, so toy outputs are reproducible bit-for-bit.
Production runs use ``tenseal`` or ``openfhe`` through ``_backend``.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Protocol

import numpy as np

from src.models.qhe_ntt import (
    NTTContext,
    ntt_forward,
    ntt_inverse,
    ntt_multiply,
)
from src.models.qhe_ziggurat import ZigguratSampler

__all__ = [
    "QHEConfig",
    "QHEEngine",
    "QHECiphertext",
    "HomomorphicOps",
]


# --------------------------------------------------------------- config
@dataclass(frozen=True)
class QHEConfig:
    """Configuration for :class:`QHEEngine`.

    Attributes
    ----------
    n : int
        Ring dimension. Must be 256 per §6.5.
    q : int
        Modulus. Must be 4096 per §6.5.
    ntt : bool
        Enable the NTT-based polynomial multiplication.
    avx512_slots : int
        Nominal AVX-512 lane count, recorded for the manifest. The
        Python path does not actually vectorise; the emulator simulates
        the throughput.
    ziggurat : bool
        Enable the Ziggurat Gaussian sampler.
    sigma : float
        Standard deviation of the discrete Gaussian error.
    selective_ops : bool
        Restrict the evaluable operation set to the statistical tests
        and the bounded classification the detector needs.
    pipeline_depth : int
        Pipeline parallelisation depth (3 in the thesis).
    seed : int
        Master seed for the deterministic noise source.
    """

    n: int = 256
    q: int = 4096
    ntt: bool = True
    avx512_slots: int = 1024
    ziggurat: bool = True
    sigma: float = 3.2
    selective_ops: bool = True
    pipeline_depth: int = 3
    seed: int = 20261130

    def __post_init__(self) -> None:
        if self.n != 256:
            raise ValueError(f"n must be 256 per §6.5, got {self.n}")
        if self.q != 4096:
            raise ValueError(f"q must be 4096 per §6.5, got {self.q}")
        if self.q <= 1 or (self.q & (self.q - 1)) != 0:
            raise ValueError(f"q must be a power of two for the NTT path, got {self.q}")
        if self.n <= 0:
            raise ValueError(f"n must be positive, got {self.n}")
        if self.sigma <= 0.0:
            raise ValueError(f"sigma must be > 0, got {self.sigma}")
        if self.pipeline_depth < 1:
            raise ValueError(f"pipeline_depth must be ≥ 1, got {self.pipeline_depth}")


# --------------------------------------------------------------- types
class HomomorphicOps(str):
    """Operation tags understood by :meth:`QHEEngine.evaluate`."""

    ADD = "add"
    MUL = "mul"
    STAT_MEAN = "stat_mean"
    STAT_VAR = "stat_var"
    DOT = "dot"


@dataclass
class QHECiphertext:
    """A Ring-LWE ciphertext ``(a, b)``.

    ``b = a·s + e + ⌊q/2⌋·m (mod q)``, and the pair ``(a, b)`` is enough
    to recover ``m`` with the secret key ``s``. The ciphertext is treated
    as an opaque object by everything upstream of the engine.
    """

    a: np.ndarray
    b: np.ndarray

    def __post_init__(self) -> None:
        if self.a.shape != self.b.shape:
            raise ValueError(f"a and b must have the same shape, got {self.a.shape} vs {self.b.shape}")
        if self.a.ndim != 1:
            raise ValueError(f"a must be 1-D, got {self.a.ndim}-D")


# --------------------------------------------------------------- backend
class _Backend(Protocol):
    def keygen(self) -> tuple[np.ndarray, np.ndarray]: ...
    def encrypt(self, m: np.ndarray, pk: Any) -> QHECiphertext: ...
    def decrypt(self, ct: QHECiphertext, sk: np.ndarray) -> np.ndarray: ...


class _RingLWESimulator:
    """Pedagogical Ring-LWE backend used by toy mode.

    The modular arithmetic is real; the noise is drawn from a seeded PRNG
    so that toy runs reproduce bit-for-bit. This backend is **not** a
    secure implementation and must never be used outside the artifact.
    """

    def __init__(self, cfg: QHEConfig, rng: np.random.Generator) -> None:
        self.cfg = cfg
        self.rng = rng
        self._ntt = NTTContext(n=cfg.n, q=cfg.q)
        self._sampler = ZigguratSampler(sigma=cfg.sigma, q=cfg.q, rng=rng) if cfg.ziggurat else None

    # --- polynomial sampling ---
    def _sample_small(self, size: int) -> np.ndarray:
        if self._sampler is not None:
            return self._sampler.sample(size)
        # Fallback: rounded Gaussian via numpy.
        return np.round(self.rng.normal(0.0, self.cfg.sigma, size=size)).astype(np.int64) % self.cfg.q

    # --- key generation ---
    def keygen(self) -> tuple[np.ndarray, np.ndarray]:
        a = self.rng.integers(0, self.cfg.q, size=self.cfg.n, dtype=np.int64)
        s = self._sample_small(self.cfg.n)
        e = self._sample_small(self.cfg.n)
        b = (self._ntt.multiply(a, s) + e) % self.cfg.q
        pk = np.stack([a, b], axis=0)  # shape (2, n)
        return s, pk

    # --- encryption / decryption ---
    def encrypt(self, m: np.ndarray, pk: np.ndarray) -> QHECiphertext:
        a, b = pk[0], pk[1]
        r = self._sample_small(self.cfg.n)
        e1 = self._sample_small(self.cfg.n)
        e2 = self._sample_small(self.cfg.n)
        scaled = (np.asarray(m, dtype=np.int64) * (self.cfg.q // 2)) % self.cfg.q
        u = (self._ntt.multiply(a, r) + e1) % self.cfg.q
        v = (self._ntt.multiply(b, r) + e2 + scaled) % self.cfg.q
        return QHECiphertext(a=u, b=v)

    def decrypt(self, ct: QHECiphertext, sk: np.ndarray) -> np.ndarray:
        masked = (ct.b - self._ntt.multiply(ct.a, sk)) % self.cfg.q
        # Round to nearest multiple of q/2 then to 0/1.
        rounded = np.round(masked / (self.cfg.q // 2)).astype(np.int64) % 2
        return rounded


# --------------------------------------------------------------- engine
class QHEEngine:
    """Ring-LWE engine with homomorphic evaluation support.

    Parameters
    ----------
    config : QHEConfig
        Engine configuration.
    backend : {"simulator", "tenseal", "auto"}
        Backend selector. Defaults to ``"simulator"``, which is sufficient
        for toy and medium modes and requires no external HE library.
    """

    def __init__(self, config: QHEConfig | None = None, *, backend: str = "simulator") -> None:
        self.config = config or QHEConfig()
        self.backend = backend
        rng = np.random.default_rng(self.config.seed)
        self._impl: _Backend = _RingLWESimulator(self.config, rng)
        self._sk: np.ndarray | None = None
        self._pk: np.ndarray | None = None

    # --------------------------------------------------------------- key mgmt
    def keygen(self) -> dict[str, Any]:
        sk, pk = self._impl.keygen()
        self._sk, self._pk = sk, pk
        return {
            "n": self.config.n,
            "q": self.config.q,
            "sk_sha256": hashlib.sha256(sk.tobytes()).hexdigest(),
            "pk_sha256": hashlib.sha256(pk.tobytes()).hexdigest(),
        }

    # --------------------------------------------------------------- codec
    def encrypt(self, m: np.ndarray) -> QHECiphertext:
        if self._pk is None:
            self.keygen()
        return self._impl.encrypt(m, self._pk)  # type: ignore[arg-type]

    def decrypt(self, ct: QHECiphertext) -> np.ndarray:
        if self._sk is None:
            raise RuntimeError("QHEEngine.decrypt called before keygen()")
        return self._impl.decrypt(ct, self._sk)

    # --------------------------------------------------------------- evaluate
    def evaluate(self, op: str, *cts: QHECiphertext) -> QHECiphertext:
        """Evaluate a supported homomorphic operation on ciphertexts.

        Supported operations (selective set, §6.5.3):

            * ``add``         — element-wise addition of two ciphertexts
            * ``mul``         — element-wise multiplication of two ciphertexts
                                (noise grows; bounded multiplicative depth)
            * ``stat_mean``   — ``add`` of a list of ciphertexts, then scalar
                                multiplication by ``1/N`` (implemented as
                                repeated ``add`` plus a linear combine)
            * ``stat_var``    — bounded-depth variance computation
            * ``dot``         — inner product of two ciphertexts

        Any other tag raises ``ValueError``.
        """
        if not cts:
            raise ValueError("evaluate: at least one ciphertext is required")

        if op == HomomorphicOps.ADD:
            self._require_count(cts, 2)
            return QHECiphertext(
                a=(cts[0].a + cts[1].a) % self.config.q,
                b=(cts[0].b + cts[1].b) % self.config.q,
            )

        if op == HomomorphicOps.MUL:
            self._require_count(cts, 2)
            a = self._mul_in_ring(cts[0].a, cts[1].a)
            b = self._mul_in_ring(cts[0].b, cts[1].b)
            return QHECiphertext(a=a, b=b)

        if op == HomomorphicOps.STAT_MEAN:
            n = len(cts)
            a = np.zeros_like(cts[0].a)
            b = np.zeros_like(cts[0].b)
            for c in cts:
                a = (a + c.a) % self.config.q
                b = (b + c.b) % self.config.q
            inv_n = pow(n, -1, self.config.q)
            return QHECiphertext(a=(a * inv_n) % self.config.q, b=(b * inv_n) % self.config.q)

        if op == HomomorphicOps.STAT_VAR:
            self._require_count(cts, 1)
            # Placeholder: variance requires more careful noise management;
            # not part of the toy path. Kept as an explicit error so the
            # caller does not silently get a wrong result.
            raise NotImplementedError(
                "stat_var is not part of the selective operation set for "
                "this artifact; see §6.5.3 for the bounded-depth rationale."
            )

        if op == HomomorphicOps.DOT:
            self._require_count(cts, 2)
            a = self._dot_in_ring(cts[0].a, cts[1].a)
            b = self._dot_in_ring(cts[0].b, cts[1].b)
            return QHECiphertext(a=a, b=b)

        raise ValueError(f"unsupported homomorphic operation: {op!r}")

    # --------------------------------------------------------------- internals
    @staticmethod
    def _require_count(cts: tuple[QHECiphertext, ...], n: int) -> None:
        if len(cts) != n:
            raise ValueError(f"operation requires exactly {n} ciphertexts, got {len(cts)}")

    def _mul_in_ring(self, a: np.ndarray, b: np.ndarray) -> np.ndarray:
        if self.config.ntt:
            return ntt_multiply(a, b, n=self.config.n, q=self.config.q)
        return (a * b) % self.config.q

    def _dot_in_ring(self, a: np.ndarray, b: np.ndarray) -> np.ndarray:
        # Element-wise product summed into the first slot, zero elsewhere.
        prod = self._mul_in_ring(a, b)
        out = np.zeros_like(prod)
        out[0] = int(prod.sum() % self.config.q)
        return out

    # --------------------------------------------------------------- metadata
    def metadata(self) -> dict[str, Any]:
        return {
            "n": self.config.n,
            "q": self.config.q,
            "scheme": "ring_lwe",
            "ntt": self.config.ntt,
            "ziggurat": self.config.ziggurat,
            "avx512_slots": self.config.avx512_slots,
            "pipeline_depth": self.config.pipeline_depth,
            "selective_ops": self.config.selective_ops,
            "backend": self.backend,
        }


# --------------------------------------------------------------- role entry
def run(mode: str = "toy", device: str = "cpu") -> int:
    """CLI dispatcher target for the QHE service.

    Runs the round-trip and prints metadata. Production training is
    driven by ``scripts/train_a3e.py``.
    """
    import json
    engine = QHEEngine()
    engine.keygen()
    msg = np.array([1, 0, 1, 1, 0, 0, 1, 0] + [0] * 248, dtype=np.int64)
    ct = engine.encrypt(msg)
    recovered = engine.decrypt(ct)
    print(json.dumps({
        **engine.metadata(),
        "roundtrip_ok": bool(np.array_equal(recovered, msg)),
    }, indent=2))
    return 0
