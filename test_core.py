import os, sys, unittest, json
import numpy as np
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from a3e_dns_v2.aee.se3 import exp_se3, hat, is_rigid, SE3State, hkdf_sha3
from a3e_dns_v2.aee import AEEEngine, sigma_from_kl, kl_divergence, diffusion_coefficient, NeuralController
from a3e_dns_v2.qhe import PARAM_SETS, RLWEAdditive, negacyclic_mul, ntt_negacyclic_mul, TableGaussianSampler, EncryptedHistogram
from a3e_dns_v2.fl import geometric_median, mad_filter, calibrate_sigma, GaussianRDPAccountant, SpatioTemporalAttention, temporal_decay, aggregate
from a3e_dns_v2.fl.simulate import MLPModel
from a3e_dns_v2.sandbox import SandboxMDP, value_iteration, kl, renyi
from a3e_dns_v2.intel import parse_stix_bundle, fuse_indicators, detect_darknet_scans
from a3e_dns_v2 import traffic as T, params

class AEE(unittest.TestCase):
    def test_exp_identity_and_rigid(self):
        self.assertTrue(np.allclose(exp_se3(np.zeros(6)), np.eye(4)))
        r = np.random.default_rng(0)
        for _ in range(200): self.assertTrue(is_rigid(exp_se3(r.standard_normal(6) * 2)))
    def test_pure_translation(self):
        T_ = exp_se3(np.array([0, 0, 0, 1, 2, 3.])); self.assertTrue(np.allclose(T_[:3, 3], [1, 2, 3]))
    def test_group_property_commuting_axis(self):
        a = exp_se3(np.array([0, 0, .3, 0, 0, 0])); b = exp_se3(np.array([0, 0, .4, 0, 0, 0])); self.assertTrue(np.allclose(a @ b, exp_se3(np.array([0, 0, .7, 0, 0, 0]))))
    def test_key_lengths_and_cadence(self):
        s = SE3State(4).step(np.random.default_rng(0).standard_normal((4, 6))); k, iv, c = s.derive(); self.assertEqual((len(k), len(iv)), (32, 12)); self.assertTrue(5 <= c <= 15)
    def test_determinism_with_seed(self):
        f = np.ones(16); a = AEEEngine(seed=4).update(f, [3, 2, 1], [2, 2, 2])[0]; b = AEEEngine(seed=4).update(f, [3, 2, 1], [2, 2, 2])[0]; self.assertEqual(a, b)
    def test_keys_change(self):
        e = AEEEngine(seed=1); f = np.ones(16); ks = {e.update(f, [3, 2, 1], [2, 2, 2])[0] for _ in range(50)}; self.assertEqual(len(ks), 50)
    def test_sigma_monotone_and_bounded(self):
        s = [sigma_from_kl(k) for k in np.linspace(0, 2, 50)]; self.assertTrue(all(np.diff(s) >= 0)); self.assertTrue(0.05 <= min(s) and max(s) <= 1.0)
    def test_diffusion_nonincreasing_and_floor(self):
        d = [diffusion_coefficient(g, 0.1, 0.5) for g in np.linspace(0, 20, 40)]; self.assertTrue(all(np.diff(d) <= 1e-12)); self.assertGreaterEqual(min(d), 0.1)
    def test_kl_nonnegative_zero_on_equal(self):
        self.assertAlmostEqual(kl_divergence([1, 2, 3], [1, 2, 3]), 0, places=9); self.assertGreater(kl_divergence([1, 2, 3], [3, 2, 1]), 0)
    def test_controller_shapes_and_quant(self):
        c = NeuralController(); x = np.random.default_rng(0).standard_normal(16); y = c(x); self.assertEqual(y.shape, (24,)); self.assertLessEqual(np.abs(c.quantize_int8()(x) - y).max(), 0.1)

class QHE(unittest.TestCase):
    def test_roundtrip_all_sets(self):
        for ps in PARAM_SETS.values():
            sc = RLWEAdditive(ps, 1); m = np.random.default_rng(0).integers(0, ps.t, ps.n); self.assertTrue(np.array_equal(sc.decrypt(sc.encrypt(m)), m))
    def test_additive_homomorphism(self):
        ps = PARAM_SETS["ntt_n256"]; sc = RLWEAdditive(ps, 2); r = np.random.default_rng(1); a, b = r.integers(0, 100, ps.n), r.integers(0, 100, ps.n)
        self.assertTrue(np.array_equal(sc.decrypt(sc.add(sc.encrypt(a), sc.encrypt(b))), (a + b) % ps.t))
    def test_scalar(self):
        ps = PARAM_SETS["ntt_n256"]; sc = RLWEAdditive(ps, 3); a = np.random.default_rng(1).integers(0, 40, ps.n); self.assertTrue(np.array_equal(sc.decrypt(sc.scale(sc.encrypt(a), 3)), (3 * a) % ps.t))
    def test_ntt_equals_convolution(self):
        ps = PARAM_SETS["ntt_n256"]; r = np.random.default_rng(0); a, b = r.integers(0, ps.q, ps.n), r.integers(0, ps.q, ps.n); self.assertTrue(np.array_equal(negacyclic_mul(a, b, ps.q), ntt_negacyclic_mul(a, b, ps.q)))
    def test_negacyclic_wraps_with_sign(self):
        a = np.zeros(8, np.int64); a[7] = 1; b = np.zeros(8, np.int64); b[1] = 1; self.assertEqual(negacyclic_mul(a, b, 97)[0], 96)
    def test_sampler_moments(self):
        x = TableGaussianSampler(1.58, seed=0).sample(200000); self.assertAlmostEqual(float(x.std()), 1.58, delta=0.02); self.assertAlmostEqual(float(x.mean()), 0, delta=0.02)
    def test_encrypted_histogram_matches_plain(self):
        sc = RLWEAdditive(PARAM_SETS["ntt_n256"], 4); eh = EncryptedHistogram(sc, np.linspace(0, 6, 17)); r = np.random.default_rng(0); v = [r.normal(3, 1, 25).clip(0, 5.9) for _ in range(10)]
        dec = eh.open(eh.aggregate([eh.report(x) for x in v])); self.assertTrue(np.array_equal(dec, np.histogram(np.concatenate(v), bins=eh.edges)[0]))
    def test_noise_budget_decreases(self):
        sc = RLWEAdditive(PARAM_SETS["ntt_n256"], 5); m = np.zeros(256, np.int64); c = sc.encrypt(m); b1 = sc.noise_budget_bits(c, m)
        for _ in range(30): c = sc.add(c, sc.encrypt(m))
        self.assertLess(sc.noise_budget_bits(c, m), b1)

class FL(unittest.TestCase):
    def test_geomed_resists_outliers(self):
        U = np.vstack([np.random.default_rng(0).standard_normal((20, 5)) * 0.1 + 1, np.full((8, 5), 100.0)]); self.assertLess(np.abs(geometric_median(U) - 1).max(), 0.5); self.assertGreater(np.abs(U.mean(0) - 1).max(), 10)
    def test_mad_filter_flags_outliers(self):
        U = np.vstack([np.random.default_rng(0).standard_normal((30, 4)) * 0.1, np.full((5, 4), 50.0)]); keep = mad_filter(U); self.assertFalse(keep[-5:].any()); self.assertTrue(keep[:30].mean() > 0.8)
    def test_accountant_monotone(self):
        a = GaussianRDPAccountant(20.0); e = [a.epsilon(t) for t in (10, 50, 100)]; self.assertTrue(e[0] < e[1] < e[2])
    def test_calibration_hits_target(self):
        s = calibrate_sigma(1.0, 100); self.assertAlmostEqual(GaussianRDPAccountant(s).epsilon(100), 1.0, delta=0.01)
    def test_decay_matrix(self):
        d = temporal_decay(10, 0.1); self.assertAlmostEqual(d[0, 0], 1.0); self.assertGreater(d[0, 1], d[0, 5])
    def test_attention_rows_sum_to_one(self):
        a = SpatioTemporalAttention(48, 12); a(np.random.default_rng(0).standard_normal((20, 48))); self.assertTrue(all(np.allclose(A.sum(-1), 1) for A in a.last_attn))
    def test_mlp_gradient(self):
        r = np.random.default_rng(0); m = MLPModel(6, 5, 1); X = r.standard_normal((4, 6)); y = np.array([0, 1, 1, 0.])
        L = lambda: -np.mean(y * np.log(m.predict_proba(X) + 1e-12) + (1 - y) * np.log(1 - m.predict_proba(X) + 1e-12)); g = m.grad(X, y, 0.0)
        for i in range(0, len(g), 5):
            w = m.w[i]; m.w[i] = w + 1e-6; a = L(); m.w[i] = w - 1e-6; b = L(); m.w[i] = w; self.assertAlmostEqual(g[i], (a - b) / 2e-6, places=5)
    def test_aggregate_methods_agree_when_clean(self):
        U = np.random.default_rng(0).standard_normal((30, 4)) * 0.05 + 0.3
        for m in ("mean", "median", "trimmed", "geomed", "mad_geomed"): self.assertLess(np.abs(aggregate(U, m)[0] - 0.3).max(), 0.1)

class Sandbox(unittest.TestCase):
    def test_vi_converges_and_policy_valid(self):
        V, pi = value_iteration(SandboxMDP()); self.assertTrue(np.all(np.isfinite(V))); self.assertTrue(set(pi) <= {0, 1, 2, 3})
    def test_rows_stochastic(self):
        P = SandboxMDP().P; self.assertTrue(np.allclose(P.sum(-1), 1))
    def test_divergences(self):
        self.assertAlmostEqual(kl([1, 1], [1, 1]), 0, places=8); self.assertGreater(renyi([9, 1], [1, 9], 2), 0)

class Intel(unittest.TestCase):
    def test_stix_parse_and_fuse(self):
        b = json.dumps({"objects": [{"type": "indicator", "pattern": "[domain-name:value = 'Evil.EXAMPLE']", "confidence": 80}, {"type": "malware"}]}); ind = parse_stix_bundle(b)
        self.assertEqual(ind[0]["value"], "evil.example"); f = fuse_indicators(ind, ind); self.assertGreater(f[("domain-name", "evil.example")]["score"], 0.8)
    def test_scan_detection(self):
        rec = [(float(i), "1.2.3.4", 1000 + i) for i in range(20)] + [(0.0, "5.6.7.8", 80), (200.0, "5.6.7.8", 81)]; self.assertIn("1.2.3.4", detect_darknet_scans(rec, 8)); self.assertNotIn("5.6.7.8", detect_darknet_scans(rec, 8))

class Traffic(unittest.TestCase):
    def test_shapes_and_labels(self):
        X, y, p, s = T.make_dataset(50, np.random.default_rng(0)); self.assertEqual(X.shape[1], 16); self.assertEqual(set(np.unique(y)), {0.0, 1.0})
    def test_every_scenario_shifts_its_features(self):
        r = np.random.default_rng(0)
        for sid, sc in T.SCENARIOS.items():
            p = "DoH" if sc.protocol == "ALL" else sc.protocol; b, a = T.benign(p, 2000, r), T.attack(sid, p, 2000, r)
            for f, sh in sc.shift.items():
                j = T.FEATURES.index(f); self.assertEqual(np.sign((a[:, j] - b[:, j]).mean()), np.sign(sh), msg=f"{sid}:{f}")


class Metrics(unittest.TestCase):
    def test_jsd_bounds(self):
        from a3e_dns_v2.metrics import jsd
        self.assertAlmostEqual(jsd([1, 2, 3], [1, 2, 3]), 0, places=8); self.assertLessEqual(jsd([1, 0], [0, 1]), np.log(2) + 1e-6)
    def test_cds_eq131_perfect(self):
        from a3e_dns_v2.metrics import cds
        y = np.array([0] * 50 + [1] * 50); s = np.concatenate([np.full(50, 0.1), np.full(50, 0.9)]); v, parts = cds(y, s, (s > 0.5).astype(int), lam=0.1)
        self.assertAlmostEqual(parts["auprc"], 1.0, places=6); self.assertAlmostEqual(parts["f1_weighted"], 1.0, places=6); self.assertAlmostEqual(v, 1.0, places=6)
    def test_auprc_random_near_prevalence(self):
        from a3e_dns_v2.metrics import auprc
        r = np.random.default_rng(0); y = (r.random(20000) < 0.3).astype(int); self.assertAlmostEqual(auprc(y, r.random(20000)), 0.3, delta=0.02)
    def test_qps_and_eta(self):
        from a3e_dns_v2.metrics import qps_max, eta_adversarial
        self.assertAlmostEqual(qps_max(100, 2, 80, 1, 1000, 10, 0.0), 50.0); self.assertAlmostEqual(qps_max(100, 2, 80, 1, 1000, 10, 0.25), 37.5)
        self.assertAlmostEqual(eta_adversarial([1, 5, 9, 2], 1.0, [3, 3, 3, 3]), 0.5)
    def test_holm(self):
        from a3e_dns_v2.metrics import holm
        a = holm([0.01, 0.04, 0.03]); self.assertTrue(np.all(a >= np.array([0.01, 0.04, 0.03]))); self.assertTrue(np.all(a <= 1))
    def test_lr_schedule(self):
        from a3e_dns_v2.fl import AdaptiveLR
        lr = AdaptiveLR(0.065, delta=1e-2); e = [lr.step(1.0, 0.5) for _ in range(30)]; self.assertAlmostEqual(e[0], 0.065); self.assertLess(e[-1], e[0]); self.assertTrue(all(np.diff(e) <= 1e-12))


class Pipeline(unittest.TestCase):
    def test_cef_and_correlation(self):
        from a3e_dns_v2.intel import parse_cef, correlate
        lines = [f"CEF:0|Lab|DNSGuard|1|{sig}|name|5|src=10.0.0.9 dst=10.0.0.2 rt={t} proto=DoH" for t, sig in ((1, "a"), (5, "b"), (9, "c"))] + ["CEF:0|Lab|X|1|z|n|3|src=10.0.0.4 rt=2"]
        ev = [parse_cef(l) for l in lines]; out = correlate(ev); self.assertEqual([o["src"] for o in out], ["10.0.0.9"])
    def test_pipeline_end_to_end(self):
        from a3e_dns_v2.pipeline import A3EPipeline
        from a3e_dns_v2.qhe import PARAM_SETS, RLWEAdditive, EncryptedHistogram
        from a3e_dns_v2.fl.simulate import MLPModel
        r = np.random.default_rng(0); X, y, p, s = T.make_dataset(100, r); mu, sd = X.mean(0), X.std(0) + 1e-9
        class Stub:
            def predict_proba(self, Z): return 1 / (1 + np.exp(-(Z[:, 6] - 1)))
        eh = EncryptedHistogram(RLWEAdditive(PARAM_SETS["ntt_n256"], 1), np.linspace(0, 6, 17)); base = np.histogram(T.benign("DoH", 5000, r)[:, 6], bins=eh.edges)[0]
        pl = A3EPipeline(Stub(), mu, sd, eh, base); res = pl.process(T.attack("S2-Tunnel", "DoH", 25, r), "DoH"); self.assertTrue(res["flagged"]); self.assertEqual(pl.state, 1)
        cts = [pl._qhe(T.attack("S2-Tunnel", "DoH", 25, r)) for _ in range(5)]; chi, alarm = pl.encrypted_verdict(cts); self.assertTrue(alarm)
        cts = [pl._qhe(T.benign("DoH", 25, r)) for _ in range(5)]; chi_b, alarm_b = pl.encrypted_verdict(cts); self.assertLess(chi_b, chi)

class Registry(unittest.TestCase):
    def test_registry(self):
        self.assertGreater(len(params.REGISTRY), 50); self.assertGreaterEqual(len(params.conflicts()), 10); self.assertIn("key,value", params.to_csv().splitlines()[0])

if __name__ == "__main__": unittest.main()
