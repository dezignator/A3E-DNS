"""Sandbox response policy (AMPS; Section 6.3.2, Section 6.14.3, Table 34a).

Table 34a describes the adaptive protocol-aware sandbox as an MDP with a Hamilton-Jacobi-Bellman optimal response. We
solve a finite-state discrete-time counterpart by value iteration so
the policy is inspectable. States: normal, suspicious, isolated, terminated.
Actions: allow, monitor, isolate, terminate. Protocol-specific action
names follow the protocol-specific actions of Section 6.17.4 and Table 34a (DoH stream termination, DoT TLS reset, DoQ connection migration handling).
"""
import numpy as np

STATES = ["normal", "suspicious", "isolated", "terminated"]
ACTIONS = ["allow", "monitor", "isolate", "terminate"]
PROTOCOL_ACTIONS = {
 "DoH": {"isolate": "HTTP/2 stream isolation", "terminate": "RST_STREAM + connection drain"},
 "DoT": {"isolate": "TLS session quarantine", "terminate": "close_notify then TCP RST"},
 "DoQ": {"isolate": "QUIC connection pinning", "terminate": "CONNECTION_CLOSE with application error"},
}

class SandboxMDP:
    def __init__(self, p_attack=0.1, p_escalate=0.35, c_fp=4.0, c_breach=40.0, c_isolate=0.6, c_monitor=0.1, gamma=0.95):
        self.g = gamma; S, A = len(STATES), len(ACTIONS)
        P = np.zeros((A, S, S)); R = np.zeros((A, S))
        # allow
        P[0, 0] = [1 - p_attack, p_attack, 0, 0]; P[0, 1] = [0.1, 0.5, 0, 0.4]; P[0, 2] = [0, 0, 1, 0]; P[0, 3] = [0, 0, 0, 1]
        # monitor: detection moves suspicious toward isolated/normal
        P[1, 0] = [1 - p_attack, p_attack, 0, 0]; P[1, 1] = [0.25, 0.45, 0.3, 0]; P[1, 2] = [0, 0, 1, 0]; P[1, 3] = [0, 0, 0, 1]
        # isolate
        P[2, 0] = [1, 0, 0, 0]; P[2, 1] = [0.05, 0, 0.95, 0]; P[2, 2] = [0.1, 0, 0.9, 0]; P[2, 3] = [0, 0, 0, 1]
        # terminate
        P[3, 0] = [1, 0, 0, 0]; P[3, 1] = [0, 0, 0, 1]; P[3, 2] = [0, 0, 0, 1]; P[3, 3] = [0, 0, 0, 1]
        R[0] = [0, -c_breach * p_escalate, 0, 0]; R[1] = [-c_monitor, -c_breach * 0.4 - c_monitor, 0, 0]
        R[2] = [-c_fp * 0.5, -c_isolate, -c_isolate, 0]; R[3] = [-c_fp * 2, -1.0, -1.0, 0]
        self.P, self.R = P, R

def value_iteration(m: SandboxMDP, tol=1e-9, max_iter=10000):
    V = np.zeros(len(STATES))
    for _ in range(max_iter):
        Q = m.R + m.g * (m.P @ V); V2 = Q.max(0)
        if np.abs(V2 - V).max() < tol: V = V2; break
        V = V2
    Q = m.R + m.g * (m.P @ V); return V, Q.argmax(0)

def rollout(m, policy, steps, rng, s0=0):
    s = s0; traj = []
    for _ in range(steps):
        a = policy[s]; traj.append((STATES[s], ACTIONS[a])); s = rng.choice(len(STATES), p=m.P[a, s])
    return traj
