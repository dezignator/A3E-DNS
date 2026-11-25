"""SE(3)^n encryption state (Section 6.4.2).

Rotational components feed the session-key derivation; translational
components feed the IV and the rotation cadence. The exponential map is
the closed-form one for se(3), so every update stays on the group.
"""
import hashlib, hmac, struct
import numpy as np

def hat(xi):
    w, v = xi[:3], xi[3:]
    M = np.zeros((4, 4))
    M[:3, :3] = np.array([[0, -w[2], w[1]], [w[2], 0, -w[0]], [-w[1], w[0], 0]])
    M[:3, 3] = v
    return M

def exp_se3(xi):
    """Closed-form exponential of a twist xi = (omega, v)."""
    w, v = np.asarray(xi[:3], float), np.asarray(xi[3:], float)
    th = np.linalg.norm(w)
    W = hat(np.concatenate([w, np.zeros(3)]))[:3, :3]
    if th < 1e-9:
        R = np.eye(3) + W; V = np.eye(3) + 0.5 * W
    else:
        A = np.sin(th) / th; B = (1 - np.cos(th)) / th**2; C = (1 - A) / th**2
        R = np.eye(3) + A * W + B * (W @ W)
        V = np.eye(3) + B * W + C * (W @ W)
    T = np.eye(4); T[:3, :3] = R; T[:3, 3] = V @ v
    return T

def hkdf_sha3(ikm: bytes, info: bytes, length: int, salt: bytes = b"a3e-dns-v2") -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha3_256).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha3_256).digest(); out += t; i += 1
    return out[:length]

def is_rigid(T, tol=1e-8):
    R = T[:3, :3]
    return np.allclose(R @ R.T, np.eye(3), atol=tol) and abs(np.linalg.det(R) - 1) < tol

class SE3State:
    """n-fold product state. Matrices are re-orthonormalised after each step."""
    def __init__(self, n=4):
        self.n = n; self.T = [np.eye(4) for _ in range(n)]

    def step(self, xis, dt=1.0):
        for k in range(self.n):
            self.T[k] = self.T[k] @ exp_se3(np.asarray(xis[k]) * dt)
            U, _, Vt = np.linalg.svd(self.T[k][:3, :3]); self.T[k][:3, :3] = U @ Vt
        return self

    def _quant(self, arr, bits=16):
        q = np.clip(np.round(np.asarray(arr).ravel() * (2**(bits - 2))), -2**15, 2**15 - 1).astype(np.int16)
        return q.tobytes()

    def derive(self, context: bytes = b""):
        """Return (session_key_32B, iv_12B, rotation_cadence_s)."""
        rot = b"".join(self._quant(T[:3, :3]) for T in self.T)
        trn = b"".join(self._quant(T[:3, 3]) for T in self.T)
        key = hkdf_sha3(rot, b"key" + context, 32)
        iv = hkdf_sha3(trn, b"iv" + context, 12)
        cadence = 5.0 + (struct.unpack(">I", hkdf_sha3(trn, b"cad", 4))[0] / 2**32) * 10.0  # 5 - 15 s
        return key, iv, cadence
