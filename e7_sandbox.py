"""E7: sandbox response policy and sensitivity (AMPS: Section 6.3.2, 6.14.3, Table 34a)."""
from common import *
import itertools
from a3e_dns_v2.sandbox import *
from a3e_dns_v2.sandbox.mdp import STATES, ACTIONS

def run():
    rows = []
    for pe, ci in itertools.product((0.005, 0.02, 0.05, 0.1, 0.35), (0.6, 2.0, 8.0)):
        m = SandboxMDP(p_escalate=pe, c_isolate=ci); V, pi = value_iteration(m)
        rows.append(dict(p_escalate=pe, c_isolate=ci, **{f"policy[{STATES[i]}]": ACTIONS[pi[i]] for i in range(4)}, **{f"V[{STATES[i]}]": V[i] for i in range(4)}))
    df = pd.DataFrame(rows); save_table(df, "e7_policy_sensitivity", "E7a. Optimal sandbox action per state across escalation probability and isolation cost (value iteration, gamma=0.95, c_breach=40)")
    m = SandboxMDP(); V, pi = value_iteration(m); r = np.random.default_rng(0); out = []
    for name, pol in (("optimal", pi), ("always_allow", np.zeros(4, int)), ("always_terminate", np.full(4, 3)), ("monitor_only", np.array([1, 1, 1, 1]))):
        costs, contain = [], []
        for _ in range(4000):
            s, c, steps, done = 1, 0.0, 0, False
            for t in range(40):
                a = pol[s]; c += -m.R[a, s] * m.g**t; s = r.choice(4, p=m.P[a, s]); steps += 1
                if s in (2, 3): done = True; break
            costs.append(c); contain.append(done)
        out.append(dict(policy=name, mean_discounted_cost=np.mean(costs), p_contained_within_40=np.mean(contain)))
    d2 = pd.DataFrame(out); save_table(d2, "e7_policy_rollouts", "E7b. Rollouts of 4000 episodes starting from the suspicious state")
    d3 = pd.DataFrame([dict(protocol=p, isolate=a["isolate"], terminate=a["terminate"]) for p, a in PROTOCOL_ACTIONS.items()]); save_table(d3, "e7_protocol_actions", "E7c. Protocol-specific realisation of sandbox actions (Section 6.17.4, Table 34a)")
    fig, ax = plt.subplots(figsize=(4.6, 3)); ax.bar(d2.policy, d2.mean_discounted_cost, color="#2c7fb8"); ax.set_ylabel("mean discounted cost"); plt.xticks(rotation=20, fontsize=7); savefig(fig, "e7_policy_rollouts"); return df, d2

if __name__ == "__main__": a, b = run(); print(a.to_string()); print(b.round(3).to_string())
