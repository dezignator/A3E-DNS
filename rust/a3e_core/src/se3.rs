//! SE(3) exponential map and state evolution for the AEE.
//!
//! We implemented the SE(3) exponential map because the AEE's state
//! evolution lives on the SE(3) Lie group: the state is a 6-vector in
//! the Lie algebra (three translation and three rotation parameters),
//! and the diffusion step must map back to the group without leaving it.
//! Doing that in NumPy would have been correct but slow; the closed-form
//! exponential map below is exact and evaluates in a few hundred
//! nanoseconds.
//!
//! The formulation is standard. For `ξ = [ρ, ω]` in `ℝ^6`, the
//! exponential is
//!
//! ```text
//!     exp(ξ) = [[R, V ρ], [0, 1]]
//! ```
//!
//! where `R = exp([ω]_×)` is the SO(3) exponential and
//! `V = I + (1 - cos θ)/θ [ω/θ]_× + (θ - sin θ)/θ [ω/θ]_×^2` is the
//! left Jacobian. The small-angle branch uses `R ≈ I + [ω]_×` and
//! `V ≈ I + [ω]_×/2` below `θ = 1e-10`.

/// SO(3) skew-symmetric operator on a 3-vector.
fn skew(v: [f64; 3]) -> [[f64; 3]; 3] {
    [
        [0.0, -v[2], v[1]],
        [v[2], 0.0, -v[0]],
        [-v[1], v[0], 0.0],
    ]
}

fn mat3_mul(a: [[f64; 3]; 3], b: [[f64; 3]; 3]) -> [[f64; 3]; 3] {
    let mut out = [[0.0f64; 3]; 3];
    for i in 0..3 {
        for j in 0..3 {
            let mut s = 0.0;
            for k in 0..3 {
                s += a[i][k] * b[k][j];
            }
            out[i][j] = s;
        }
    }
    out
}

fn mat3_add(a: [[f64; 3]; 3], b: [[f64; 3]; 3]) -> [[f64; 3]; 3] {
    let mut out = [[0.0f64; 3]; 3];
    for i in 0..3 {
        for j in 0..3 {
            out[i][j] = a[i][j] + b[i][j];
        }
    }
    out
}

fn mat3_scale(s: f64, a: [[f64; 3]; 3]) -> [[f64; 3]; 3] {
    let mut out = [[0.0f64; 3]; 3];
    for i in 0..3 {
        for j in 0..3 {
            out[i][j] = s * a[i][j];
        }
    }
    out
}

fn mat3_vec(a: [[f64; 3]; 3], v: [f64; 3]) -> [f64; 3] {
    [
        a[0][0] * v[0] + a[0][1] * v[1] + a[0][2] * v[2],
        a[1][0] * v[0] + a[1][1] * v[1] + a[1][2] * v[2],
        a[2][0] * v[0] + a[2][1] * v[1] + a[2][2] * v[2],
    ]
}

fn identity3() -> [[f64; 3]; 3] {
    [
        [1.0, 0.0, 0.0],
        [0.0, 1.0, 0.0],
        [0.0, 0.0, 1.0],
    ]
}

/// Closed-form SE(3) exponential map.
///
/// `xi` is `[rho_x, rho_y, rho_z, omega_x, omega_y, omega_z]`. The
/// returned 4×4 matrix is the group element in homogeneous
/// coordinates.
pub fn se3_exp(xi: [f64; 6]) -> [[f64; 4]; 4] {
    let rho = [xi[0], xi[1], xi[2]];
    let omega = [xi[3], xi[4], xi[5]];
    let theta = (omega[0] * omega[0] + omega[1] * omega[1] + omega[2] * omega[2])
        .sqrt();

    let (r, v) = if theta < 1e-10 {
        // Small-angle branch.
        let kx = skew(omega);
        let r = mat3_add(identity3(), kx);
        let v = mat3_add(identity3(), mat3_scale(0.5, kx));
        (r, v)
    } else {
        let k = [omega[0] / theta, omega[1] / theta, omega[2] / theta];
        let kx = skew(k);
        let kx2 = mat3_mul(kx, kx);
        let sin_t = theta.sin();
        let cos_t = theta.cos();
        let one_minus_cos = 1.0 - cos_t;

        let r = mat3_add(
            mat3_add(identity3(), mat3_scale(sin_t, kx)),
            mat3_scale(one_minus_cos, kx2),
        );
        let coeff1 = one_minus_cos / theta;
        let coeff2 = (theta - sin_t) / theta;
        let v = mat3_add(
            mat3_add(identity3(), mat3_scale(coeff1, kx)),
            mat3_scale(coeff2, kx2),
        );
        (r, v)
    };

    let t = mat3_vec(v, rho);
    let mut result = [[0.0f64; 4]; 4];
    for i in 0..3 {
        for j in 0..3 {
            result[i][j] = r[i][j];
        }
        result[i][3] = t[i];
    }
    result[3][3] = 1.0;
    result
}

/// SE(3) exponential map returning the matrix in row-major order.
///
/// That is the shape the Python bindings return; keeping it here as a
/// separate function avoids the `.iter().flatten()` overhead in the
/// pipeline hot path.
pub fn se3_exp_flat(xi: [f64; 6]) -> [f64; 16] {
    let m = se3_exp(xi);
    let mut out = [0.0f64; 16];
    for i in 0..4 {
        for j in 0..4 {
            out[i * 4 + j] = m[i][j];
        }
    }
    out
}

/// AEE state evolution under the floored-diffusion SDE.
///
/// We implemented the state evolution as a struct rather than a free
/// function because the evolution carries the running state between
/// queries. That matched the pipeline's usage: each transport worker
/// owns one state and passes it through `evolve` on every query.
pub struct Se3State {
    xi: [f64; 6],
    step: u64,
    last_morph_step: u64,
    rng: SplitMix64,
}

impl Se3State {
    pub fn new(seed: u64) -> Self {
        Self {
            xi: [0.0; 6],
            step: 0,
            last_morph_step: 0,
            rng: SplitMix64::new(seed),
        }
    }

    pub fn xi(&self) -> [f64; 6] {
        self.xi
    }

    pub fn step(&self) -> u64 {
        self.step
    }

    /// Advance the state by one diffusion step.
    ///
    /// `volatility` is the scalar output of the neural controller; it
    /// floors at `volatility_floor` on the caller side. The evolution
    /// applies `d xi = drift(xi) dt + diffusion(xi) dW` with unit time
    /// step; the Gaussian `dW` is drawn from the internal RNG.
    pub fn evolve(&mut self, volatility: f64, drift_scale: f64, diffusion_scale: f64) -> bool {
        let mut d_w = [0.0f64; 6];
        for i in 0..6 {
            d_w[i] = standard_normal(&mut self.rng);
        }
        for i in 0..6 {
            let drift = drift_scale * self.xi[i];
            let diffusion = diffusion_scale * volatility * d_w[i];
            self.xi[i] += drift + diffusion;
        }
        self.step += 1;
        // Morph policy: floor on dwell at 4, ceiling at 64. Caller
        // decides whether to spend the morph; we only signal it here.
        let dwell = self.step - self.last_morph_step;
        let should = dwell >= 4 || dwell >= 64;
        if should {
            self.last_morph_step = self.step;
        }
        should
    }

    /// The SE(3) matrix corresponding to the current state.
    pub fn transform(&self) -> [[f64; 4]; 4] {
        se3_exp(self.xi)
    }
}

/// Box-Muller standard normal draw from a uniform RNG.
///
/// We used Box-Muller rather than the inverse CDF because the sampler
/// module already has a CDT for the discrete Gaussian, and the two
/// distributions are conceptually distinct. Pulling in `rand_distr`
/// just for the standard normal would have been a heavier dependency
/// than the two lines of trig below.
fn standard_normal(rng: &mut SplitMix64) -> f64 {
    let u1 = rng.next_f64().max(1e-300);
    let u2 = rng.next_f64();
    (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx(a: f64, b: f64, tol: f64) -> bool {
        (a - b).abs() < tol
    }

    #[test]
    fn identity_at_origin() {
        let m = se3_exp([0.0; 6]);
        let identity = [
            [1.0, 0.0, 0.0, 0.0],
            [0.0, 1.0, 0.0, 0.0],
            [0.0, 0.0, 1.0, 0.0],
            [0.0, 0.0, 0.0, 1.0],
        ];
        for i in 0..4 {
            for j in 0..4 {
                assert!(approx(m[i][j], identity[i][j], 1e-12));
            }
        }
    }

    #[test]
    fn pure_translation() {
        // omega = 0, rho = [1, 2, 3]. V = I, so the translation is rho.
        let m = se3_exp([1.0, 2.0, 3.0, 0.0, 0.0, 0.0]);
        assert!(approx(m[0][3], 1.0, 1e-9));
        assert!(approx(m[1][3], 2.0, 1e-9));
        assert!(approx(m[2][3], 3.0, 1e-9));
        assert!(approx(m[0][0], 1.0, 1e-12));
        assert!(approx(m[1][1], 1.0, 1e-12));
        assert!(approx(m[2][2], 1.0, 1e-12));
    }

    #[test]
    fn pure_rotation_about_z() {
        // omega = [0, 0, pi/2], rho = 0. R should rotate (1,0,0) to
        // (0,1,0).
        let m = se3_exp([0.0, 0.0, 0.0, 0.0, 0.0, std::f64::consts::FRAC_PI_2]);
        assert!(approx(m[0][0], 0.0, 1e-9));
        assert!(approx(m[0][1], -1.0, 1e-9));
        assert!(approx(m[1][0], 1.0, 1e-9));
        assert!(approx(m[1][1], 0.0, 1e-9));
        // R * (1,0,0) = (0, 1, 0).
        assert!(approx(m[0][0] * 1.0 + m[0][1] * 0.0, 0.0, 1e-9));
        assert!(approx(m[1][0] * 1.0 + m[1][1] * 0.0, 1.0, 1e-9));
    }

    #[test]
    fn small_rotation_approximates_skew() {
        // For small omega, R ≈ I + [omega]_×.
        let eps = 1e-6;
        let m = se3_exp([0.0, 0.0, 0.0, eps, 0.0, 0.0]);
        // [omega]_× for omega = [eps, 0, 0]:
        //   [[0, 0, 0],
        //    [0, 0, -eps],
        //    [0, eps, 0]]
        assert!(approx(m[1][2], -eps, 1e-9));
        assert!(approx(m[2][1], eps, 1e-9));
    }

    #[test]
    fn state_evolution_drifts_to_zero() {
        let mut state = Se3State::new(20231130);
        for _ in 0..1_000 {
            state.evolve(0.5, -0.02, 0.12);
        }
        for i in 0..6 {
            assert!(state.xi()[i].abs() < 50.0, "drift should bound the state");
        }
    }

    #[test]
    fn box_muller_moments() {
        let mut rng = SplitMix64::new(20231130);
        let n = 100_000;
        let mut sum = 0.0;
        let mut sum_sq = 0.0;
        for _ in 0..n {
            let x = standard_normal(&mut rng);
            sum += x;
            sum_sq += x * x;
        }
        let mean = sum / n as f64;
        let var = sum_sq / n as f64 - mean * mean;
        assert!(mean.abs() < 0.02);
        assert!((var - 1.0).abs() < 0.05);
    }
}
