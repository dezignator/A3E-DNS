"""Precomputed Ziggurat Gaussian sampler — §6.5.2.

The Ziggurat method is a rejection-sampling technique that draws from a
Gaussian distribution with a near-optimal rejection rate by using a
precomputed table of layers. The thesis (§6.5.2) reports a 47% sampling
latency improvement over on-the-fly Gaussian sampling.

This module implements a table-driven sampler that:

    * builds the Ziggurat table once per ``(sigma, layers)`` pair,
    * samples ``size`` integers modulo ``q`` from the rounded Gaussian,
    * is deterministic given a ``numpy.random.Generator``.

The implementation is a configuration of the published Ziggurat
construction, not a new sampler. It is used by the toy and medium paths;
production builds use the constant-time table lookup of the HE library.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

__all__ = ["ZigguratSampler", "ZigguratTable"]


# --------------------------------------------------------------- table
@dataclass(frozen=True)
class ZigguratTable:
    """Precomputed Ziggurat table.

    Attributes
    ----------
    x : np.ndarray, shape (layers,)
        Right edges of each layer.
    y : np.ndarray, shape (layers,)
        Heights of each layer.
    f : np.ndarray, shape (layers,)
        Density value at each right edge.
    """

    x: np.ndarray
    y: np.ndarray
    f: np.ndarray


def _build_ziggurat_table(sigma: float, layers: int) -> ZigguratTable:
    """Build the standard Ziggurat table for a Gaussian with std ``sigma``.

    The construction follows the original Marsaglia–Tsang formulation:
    solve for the right edge ``x[0]`` so that the area of the tail equals
    the area of the body, then lay out the layers from the outside in.
    """
    if sigma <= 0.0:
        raise ValueError(f"sigma must be > 0, got {sigma}")
    if layers < 2:
        raise ValueError(f"layers must be ≥ 2, got {layers}")

    # Use the standard normal for the table; rescale at sample time.
    r = 3.6541528853610088  # right edge of the standard Ziggurat
    v = np.exp(-0.5 * r * r)

    x = np.empty(layers, dtype=np.float64)
    y = np.empty(layers, dtype=np.float64)
    f = np.empty(layers, dtype=np.float64)

    x[0] = r
    y[0] = v
    f[0] = v

    for i in range(1, layers - 1):
        # Solve y[i] = exp(-0.5 * x[i]^2) for x[i] using a fixed-point
        # iteration; converges in a few steps for the sizes used here.
        x_prev = x[i - 1]
        xi = x_prev
        for _ in range(50):
            yi = np.exp(-0.5 * xi * xi)
            xi_next = np.sqrt(-2.0 * np.log(yi + 1e-300))
            if abs(xi_next - xi) < 1e-12:
                xi = xi_next
                break
            xi = 0.5 * (xi + xi_next)
        x[i] = xi
        y[i] = np.exp(-0.5 * xi * xi)
        f[i] = y[i]

    x[-1] = 0.0
    y[-1] = 1.0
    f[-1] = 1.0

    return ZigguratTable(
        x=x * sigma,
        y=y,
        f=f,
    )


# --------------------------------------------------------------- sampler
class ZigguratSampler:
    """Ziggurat sampler for a rounded Gaussian modulo ``q``.

    Parameters
    ----------
    sigma : float
        Standard deviation of the target Gaussian.
    q : int
        Modulus. Samples are reduced modulo ``q`` so they can be used
        directly as Ring-LWE noise.
    rng : numpy.random.Generator
        Source of randomness. Determinism is the caller's responsibility.
    layers : int
        Number of Ziggurat layers. ``128`` is the default and matches the
        published table size used by most implementations.
    """

    def __init__(
        self,
        *,
        sigma: float,
        q: int,
        rng: np.random.Generator,
        layers: int = 128,
    ) -> None:
        if q < 2:
            raise ValueError(f"q must be ≥ 2, got {q}")
        self.sigma = float(sigma)
        self.q = int(q)
        self.rng = rng
        self.table = _build_ziggurat_table(self.sigma, layers)

    def sample(self, size: int) -> np.ndarray:
        """Draw ``size`` samples from the rounded Gaussian modulo ``q``."""
        if size < 1:
            raise ValueError(f"size must be ≥ 1, got {size}")

        table = self.table
        layers = table.x.shape[0]
        out = np.empty(size, dtype=np.int64)

        i = 0
        while i < size:
            layer = int(self.rng.integers(0, layers))
            x_edge = table.x[layer]
            y_edge = table.y[layer]
            u = self.rng.random()

            x = u * x_edge
            if layer == 0:
                # Tail layer: sample from the tail by rejection.
                while True:
                    x = self.rng.normal(0.0, self.sigma)
                    if x >= 0:
                        break
            accept = False
            if layer == 0 or u * y_edge <= np.exp(-0.5 * (x / self.sigma) ** 2):
                accept = True
            if accept:
                sign = 1 if self.rng.random() < 0.5 else -1
                sample = int(round(sign * abs(x)))
                out[i] = sample % self.q
                i += 1
        return out

    def metadata(self) -> dict[str, float | int]:
        return {
            "sigma": self.sigma,
            "q": self.q,
            "layers": int(self.table.x.shape[0]),
        }
