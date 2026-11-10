"""Number Theoretic Transform (NTT) for Ring-LWE — §6.5.1.

Provides the ``O(n log n)`` polynomial multiplication that replaces the
``O(n²)`` schoolbook convolution. The NTT is the standard transform used
by every published Ring-LWE implementation; this module is the
configuration of that published construction, not a new algorithm.

The implementation is pure NumPy, works modulo the ``q`` in
``QHEConfig`` (which is a power of two for the toy path), and uses a
negacyclic NTT suitable for the ring ``Z_q[x]/(x^n + 1)`` with ``n`` a
power of two.

For ``q`` that is not prime, the negacyclic NTT still works provided the
required primitive root of unity exists; the toy path uses ``q = 4096``
and ``n = 256``, and the engine constructs the context accordingly.

Production builds should use ``tenseal`` or ``openfhe`` for the real
constant-time, side-channel-resistant implementation. This module is the
reference path for the artifact.
"""

from __future__ import annotations

import numpy as np

__all__ = [
    "NTTContext",
    "ntt_forward",
    "ntt_inverse",
    "ntt_multiply",
    "negacyclic_multiply",
]


class NTTContext:
    """Precomputed NTT tables for a fixed ``(n, q)`` pair.

    The context caches the twiddle factors and the inverse tables, so
    repeated multiplications do not re-pay the setup cost. Contexts are
    cheap to instantiate and should be created once per engine.

    Parameters
    ----------
    n : int
        Ring dimension (power of two).
    q : int
        Modulus. The negacyclic NTT requires a primitive ``2n``-th root of
        unity modulo ``q``. For prime ``q`` and ``n`` a power of two with
        ``2n | (q − 1)``, such a root always exists.
    """

    def __init__(self, n: int, q: int) -> None:
        if n < 1 or (n & (n - 1)) != 0:
            raise ValueError(f"n must be a power of two, got {n}")
        if q < 2:
            raise ValueError(f"q must be ≥ 2, got {q}")
        self.n = n
        self.q = q
        self._root = self._find_primitive_2n_root(n, q)
        self._root_inv = pow(self._root, -1, q)
        # Bit-reversal permutation
        bits = n.bit_length() - 1
        self._bit_reverse = np.array(
            [self._reverse_bits(i, bits) for i in range(n)],
            dtype=np.int64,
        )

    # --------------------------------------------------------------- setup
    @staticmethod
    def _reverse_bits(x: int, bits: int) -> int:
        return int(f"{x:0{bits}b}"[::-1], 2)

    @staticmethod
    def _find_primitive_2n_root(n: int, q: int) -> int:
        """Return a primitive ``2n``-th root of unity modulo ``q``.

        For prime ``q`` we use the standard generator search. For
        composite ``q`` (including ``q = 4096``) we use the multiplicative
        group of ``Z_q`` and find an element of order exactly ``2n`` via
        a direct order check. Raises ``ValueError`` if no such element
        exists, so the caller is never silently given a broken table.
        """
        target_order = 2 * n
        # Fast path for prime q.
        if _is_probable_prime(q):
            g = _find_generator(q)
            root = pow(g, (q - 1) // target_order, q)
            if pow(root, target_order, q) == 1 and all(
                pow(root, target_order // p, q) != 1 for p in _prime_factors(target_order)
            ):
                return root
            raise ValueError(f"no primitive {target_order}-th root of unity mod q={q}")
        # Composite q: direct search over units.
        for candidate in range(2, q):
            if _gcd(candidate, q) != 1:
                continue
            if pow(candidate, target_order, q) != 1:
                continue
            # Order must be exactly 2n.
            if all(pow(candidate, target_order // p, q) != 1 for p in _prime_factors(target_order)):
                return candidate
        raise ValueError(f"no primitive {target_order}-th root of unity mod q={q}")

    # --------------------------------------------------------------- API
    def multiply(self, a: np.ndarray, b: np.ndarray) -> np.ndarray:
        """Negacyclic convolution of ``a`` and ``b`` modulo ``q``."""
        return ntt_multiply(a, b, n=self.n, q=self.q, context=self)

    # --------------------------------------------------------------- internals
    @property
    def root(self) -> int:
        return self._root

    @property
    def root_inv(self) -> int:
        return self._root_inv

    @property
    def bit_reverse(self) -> np.ndarray:
        return self._bit_reverse


# --------------------------------------------------------------- public API
def ntt_forward(a: np.ndarray, n: int, q: int, context: NTTContext | None = None) -> np.ndarray:
    """Forward negacyclic NTT.

    The input is a length-``n`` integer array; the output is the NTT of
    ``a`` in the ring ``Z_q[x]/(x^n + 1)``. The implementation uses an
    iterative Cooley–Tukey butterfly with precomputed twiddles.
    """
    ctx = context or NTTContext(n=n, q=q)
    return _ntt(a, ctx, inverse=False)


def ntt_inverse(a: np.ndarray, n: int, q: int, context: NTTContext | None = None) -> np.ndarray:
    """Inverse negacyclic NTT."""
    ctx = context or NTTContext(n=n, q=q)
    return _ntt(a, ctx, inverse=True)


def ntt_multiply(
    a: np.ndarray,
    b: np.ndarray,
    *,
    n: int,
    q: int,
    context: NTTContext | None = None,
) -> np.ndarray:
    """Multiply two polynomials in ``Z_q[x]/(x^n + 1)`` via NTT."""
    if a.shape != b.shape or a.shape != (n,):
        raise ValueError(f"expected shape ({n},), got {a.shape} and {b.shape}")
    ctx = context or NTTContext(n=n, q=q)
    a_hat = _ntt(a, ctx, inverse=False)
    b_hat = _ntt(b, ctx, inverse=False)
    c_hat = (a_hat * b_hat) % q
    return _ntt(c_hat, ctx, inverse=True)


def negacyclic_multiply(a: np.ndarray, b: np.ndarray, *, q: int) -> np.ndarray:
    """Schoolbook negacyclic multiplication (reference, O(n²)).

    Used by tests to validate the NTT path.
    """
    if a.shape != b.shape:
        raise ValueError(f"shape mismatch: {a.shape} vs {b.shape}")
    n = a.shape[0]
    out = np.zeros(n, dtype=np.int64)
    for i in range(n):
        for j in range(n):
            k = i + j
            sign = 1
            if k >= n:
                k -= n
                sign = -1
            out[k] = (out[k] + sign * int(a[i]) * int(b[j])) % q
    return out % q


# --------------------------------------------------------------- internals
def _ntt(a: np.ndarray, ctx: NTTContext, *, inverse: bool) -> np.ndarray:
    a = np.asarray(a, dtype=np.int64)
    n = ctx.n
    q = ctx.q
    if a.shape != (n,):
        raise ValueError(f"NTT expects shape ({n},), got {a.shape}")

    a = a.copy()
    a = a[ctx.bit_reverse]

    length = 2
    while length <= n:
        root = pow(ctx.root_inv if inverse else ctx.root, n // length, q)
        for i in range(0, n, length):
            w = 1
            for j in range(i, i + length // 2):
                u = int(a[j])
                v = int(a[j + length // 2]) * w % q
                a[j] = (u + v) % q
                a[j + length // 2] = (u - v) % q
                w = w * root % q
        length *= 2

    if inverse:
        n_inv = pow(n, -1, q)
        a = (a * n_inv) % q
    return a


def _is_probable_prime(n: int) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n == p:
            return True
        if n % p == 0:
            return False
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _find_generator(q: int) -> int:
    """Return a generator of ``Z_q^*`` for prime ``q``."""
    phi = q - 1
    factors = _prime_factors(phi)
    for g in range(2, q):
        if all(pow(g, phi // p, q) != 1 for p in factors):
            return g
    raise ValueError(f"no generator found for prime q={q}")


def _prime_factors(n: int) -> list[int]:
    factors: list[int] = []
    d = 2
    while d * d <= n:
        if n % d == 0:
            factors.append(d)
            while n % d == 0:
                n //= d
        d += 1
    if n > 1:
        factors.append(n)
    return factors


def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a
