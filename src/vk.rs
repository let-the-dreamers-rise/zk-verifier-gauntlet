//! Parse a snarkjs `verification_key.json` into arkworks BN254 types and run
//! static soundness lints on it.
//!
//! The lints here need no proving: they are cheap, deterministic checks a
//! curator (or a CI job) can run on any Groth16 verifier before it is ever
//! deployed. They catch the whole "malformed trusted setup" class, including
//! the delta == gamma flaw that cost FoomCash $2.26M and that the ZKAMA
//! `zk-polka-sdk` reproduces on every circuit it compiles.

use ark_bn254::{Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::Zero;
use num_bigint::BigUint;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct SnarkjsVk {
    pub protocol: String,
    pub curve: String,
    #[serde(rename = "nPublic")]
    pub n_public: usize,
    pub vk_alpha_1: Vec<String>,
    pub vk_beta_2: Vec<Vec<String>>,
    pub vk_gamma_2: Vec<Vec<String>>,
    pub vk_delta_2: Vec<Vec<String>>,
    #[serde(rename = "IC")]
    pub ic: Vec<Vec<String>>,
}

/// A parsed verification key in arkworks form.
pub struct Vk {
    pub alpha: G1Affine,
    pub beta: G2Affine,
    pub gamma: G2Affine,
    pub delta: G2Affine,
    pub ic: Vec<G1Affine>,
    pub n_public: usize,
}

fn fq(s: &str) -> Result<Fq, String> {
    let n: BigUint = s.parse().map_err(|_| format!("bad Fq decimal: {s}"))?;
    Ok(Fq::from(n))
}

/// snarkjs stores a G1 point as `[x, y, z]` decimal strings in affine-with-z
/// form (z is "1" for a finite point, "0" for infinity).
fn g1(v: &[String]) -> Result<G1Affine, String> {
    if v.len() < 3 {
        return Err("G1 needs 3 coords".to_string());
    }
    let z: BigUint = v[2].parse().map_err(|_| "bad G1 z")?;
    if z.is_zero() {
        return Ok(G1Affine::identity());
    }
    Ok(G1Affine::new_unchecked(fq(&v[0])?, fq(&v[1])?))
}

/// snarkjs stores a G2 point as `[[x.c0, x.c1], [y.c0, y.c1], [z.c0, z.c1]]`.
fn g2(v: &[Vec<String>]) -> Result<G2Affine, String> {
    if v.len() < 3 {
        return Err("G2 needs 3 coord pairs".to_string());
    }
    let z0: BigUint = v[2][0].parse().map_err(|_| "bad G2 z0")?;
    if z0.is_zero() {
        return Ok(G2Affine::identity());
    }
    let x = Fq2::new(fq(&v[0][0])?, fq(&v[0][1])?);
    let y = Fq2::new(fq(&v[1][0])?, fq(&v[1][1])?);
    Ok(G2Affine::new_unchecked(x, y))
}

impl Vk {
    pub fn from_snarkjs(j: &SnarkjsVk) -> Result<Vk, String> {
        if j.protocol != "groth16" {
            return Err(format!("protocol {} is not groth16", j.protocol));
        }
        if j.curve != "bn128" && j.curve != "bn254" {
            return Err(format!("curve {} is not bn254", j.curve));
        }
        let ic = j.ic.iter().map(|p| g1(p)).collect::<Result<Vec<_>, _>>()?;
        Ok(Vk {
            alpha: g1(&j.vk_alpha_1)?,
            beta: g2(&j.vk_beta_2)?,
            gamma: g2(&j.vk_gamma_2)?,
            delta: g2(&j.vk_delta_2)?,
            ic,
            n_public: j.n_public,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Severity {
    Critical,
    High,
    Warn,
}

#[derive(Debug, Clone)]
pub struct Lint {
    pub id: &'static str,
    pub severity: Severity,
    pub ok: bool,
    pub detail: String,
}

impl Lint {
    fn new(id: &'static str, severity: Severity, ok: bool, detail: impl Into<String>) -> Lint {
        Lint { id, severity, ok, detail: detail.into() }
    }
}

fn g1_on_curve_in_subgroup(p: &G1Affine) -> bool {
    // identity is a valid group element
    p.is_zero() || (p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve())
}
fn g2_on_curve_in_subgroup(p: &G2Affine) -> bool {
    p.is_zero() || (p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve())
}

/// Run every static lint. Returns one `Lint` per check; `ok == false` is a hit.
pub fn lint(vk: &Vk) -> Vec<Lint> {
    let mut out = Vec::new();
    let gen2 = G2Affine::generator();

    // 1. Structural: IC length must be nPublic + 1.
    out.push(Lint::new(
        "ic-length",
        Severity::High,
        vk.ic.len() == vk.n_public + 1,
        format!("IC has {} points, expected nPublic+1 = {}", vk.ic.len(), vk.n_public + 1),
    ));

    // 2. Every curve point must be on-curve AND in the prime-order subgroup.
    //    An off-subgroup delta/gamma/IC point is a classic small-subgroup /
    //    malleability vector.
    let mut subgroup_ok = g1_on_curve_in_subgroup(&vk.alpha)
        && g2_on_curve_in_subgroup(&vk.beta)
        && g2_on_curve_in_subgroup(&vk.gamma)
        && g2_on_curve_in_subgroup(&vk.delta);
    for p in &vk.ic {
        subgroup_ok &= g1_on_curve_in_subgroup(p);
    }
    out.push(Lint::new(
        "points-in-subgroup",
        Severity::High,
        subgroup_ok,
        "alpha/beta/gamma/delta and all IC points on-curve and in the r-order subgroup",
    ));

    // 3. No structural element may be the identity. A zero delta or gamma, or a
    //    zero IC[0], collapses the pairing equation.
    let no_identity = !vk.alpha.is_zero()
        && !vk.beta.is_zero()
        && !vk.gamma.is_zero()
        && !vk.delta.is_zero()
        && vk.ic.first().map(|p| !p.is_zero()).unwrap_or(false);
    out.push(Lint::new(
        "no-identity-element",
        Severity::High,
        no_identity,
        "alpha, beta, gamma, delta and IC[0] are all non-identity",
    ));

    // 4. THE forgery lints. In a snarkjs Groth16 key, gamma_2 is fixed to the
    //    G2 generator by construction and only delta_2 is randomised by the
    //    phase-2 contribution. So:
    //    - delta_2 == gamma_2 means the public-input term and the proof's C
    //      term pair against the same G2 point, letting C cancel vk_x for ANY
    //      public inputs: a universal forgery (the FoomCash $2.26M flaw).
    //    - delta_2 == G2 generator means the phase-2 contribution was skipped
    //      entirely, so the toxic waste is public. snarkjs' bare `groth16
    //      setup` output is exactly this, and ZKAMA/zk-polka-sdk ships it
    //      because `compile.js` never runs `zkey contribute`.
    //    (gamma_2 == generator is NOT flagged: that is the correct,
    //    by-construction value, not a defect.)
    out.push(Lint::new(
        "delta-ne-gamma",
        Severity::Critical,
        vk.delta != vk.gamma,
        "delta_2 != gamma_2 (equal => universal forgery, the FoomCash/ZKAMA flaw)",
    ));
    out.push(Lint::new(
        "delta-not-generator",
        Severity::Critical,
        vk.delta != gen2,
        "delta_2 is not the G2 generator (generator => trusted setup never contributed)",
    ));

    out
}

/// Compute vk_x = IC[0] + Σ pub_i · IC[i] for a public-input vector.
pub fn vk_x(vk: &Vk, public: &[Fr]) -> Result<G1Affine, String> {
    use ark_ec::CurveGroup;
    if public.len() + 1 != vk.ic.len() {
        return Err(format!(
            "expected {} public inputs, got {}",
            vk.ic.len() - 1,
            public.len()
        ));
    }
    let mut acc = vk.ic[0].into_group();
    for (i, s) in public.iter().enumerate() {
        acc += vk.ic[i + 1] * s;
    }
    Ok(acc.into_affine())
}
