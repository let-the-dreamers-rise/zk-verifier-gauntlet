//! A reference Groth16 pairing check in pure Rust (arkworks), used by the
//! gauntlet to confirm — offline, with no chain — that a forged proof actually
//! satisfies the verification equation the on-chain contract enforces. The
//! on-chain differential runner (`differential.rs`) then re-confirms the same
//! proof against the real PolkaVM and EVM verifiers.

use crate::vk::{vk_x, Vk};
use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::pairing::Pairing;

/// Returns true iff `(a, b, c)` verifies against `vk` for `public`.
/// Mirrors snarkjs' Solidity verifier:
///   e(-A, B) · e(alpha, beta) · e(vk_x, gamma) · e(C, delta) == 1
pub fn groth16_verify(
    vk: &Vk,
    a: G1Affine,
    b: G2Affine,
    c: G1Affine,
    public: &[Fr],
) -> Result<bool, String> {
    let vkx = vk_x(vk, public)?;
    let neg_a = -a;
    let lhs = Bn254::multi_pairing(
        [neg_a, vk.alpha, vkx, c],
        [b, vk.beta, vk.gamma, vk.delta],
    );
    Ok(lhs.0.is_one())
}

use ark_ff::One;
