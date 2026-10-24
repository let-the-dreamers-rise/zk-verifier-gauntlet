//! zk-verifier-gauntlet: a soundness harness for ZK proof verifiers deployed on
//! Polkadot Hub / PolkaVM (pallet-revive). Static VK lints, a universal-forgery
//! constructor for malformed trusted setups, and a reference pairing check.

pub mod forge;
pub mod verify;
pub mod vk;

#[cfg(test)]
mod tests {
    use crate::{forge, verify, vk};
    use ark_bn254::Fr;
    use ark_ff::PrimeField;

    fn load(name: &str) -> vk::Vk {
        let s = std::fs::read_to_string(format!("fixtures/{name}")).unwrap();
        let j: vk::SnarkjsVk = serde_json::from_str(&s).unwrap();
        vk::Vk::from_snarkjs(&j).unwrap()
    }

    fn fr(n: u64) -> Fr {
        Fr::from(n)
    }

    #[test]
    fn forgeable_vk_fails_the_forgery_lint() {
        let v = load("forgeable_vk.json");
        let lints = vk::lint(&v);
        let crit: Vec<_> = lints.iter().filter(|l| !l.ok).map(|l| l.id).collect();
        assert!(crit.contains(&"delta-ne-gamma"), "should flag delta==gamma");
        assert!(crit.contains(&"delta-not-generator"), "should flag delta==generator");
    }

    #[test]
    fn honest_vk_passes_every_lint() {
        let v = load("honest_vk.json");
        for l in vk::lint(&v) {
            assert!(l.ok, "honest VK should pass {} ({})", l.id, l.detail);
        }
    }

    #[test]
    fn forged_proof_satisfies_the_verification_equation() {
        // The whole point: on a delta==gamma VK we can forge a proof for an
        // arbitrary public input and the reference verifier accepts it.
        let v = load("forgeable_vk.json");
        let public = vec![fr(7)]; // a value no honest prover of this circuit could output
        let p = forge::forge(&v, &public).unwrap();

        // Rebuild arkworks points from the forged decimal strings and check.
        let a = parse_g1(&p.p_a);
        // p_b is emitted swapped (c1,c0) for Solidity; swap back for arkworks.
        let b = parse_g2_swapped(&p.p_b);
        let c = parse_g1(&p.p_c);
        assert!(
            verify::groth16_verify(&v, a, b, c, &public).unwrap(),
            "forged proof must verify"
        );

        // Control: flipping one coordinate must break it.
        let mut bad = a;
        bad = flip(bad);
        assert!(
            !verify::groth16_verify(&v, bad, b, c, &public).unwrap(),
            "tampered proof must be rejected"
        );
    }

    #[test]
    fn honest_vk_is_not_forgeable() {
        let v = load("honest_vk.json");
        assert!(forge::forge(&v, &[fr(1)]).is_err());
    }

    // ---- tiny parse helpers for the test ----
    use ark_bn254::{Fq, Fq2, G1Affine, G2Affine};
    use num_bigint::BigUint;
    fn q(s: &str) -> Fq {
        Fq::from(s.parse::<BigUint>().unwrap())
    }
    fn parse_g1(p: &[String; 2]) -> G1Affine {
        G1Affine::new(q(&p[0]), q(&p[1]))
    }
    fn parse_g2_swapped(p: &[[String; 2]; 2]) -> G2Affine {
        let x = Fq2::new(q(&p[0][1]), q(&p[0][0]));
        let y = Fq2::new(q(&p[1][1]), q(&p[1][0]));
        G2Affine::new(x, y)
    }
    fn flip(p: G1Affine) -> G1Affine {
        use ark_ec::AffineRepr;
        let (x, y) = p.xy().unwrap();
        G1Affine::new_unchecked(*x + Fq::from(1u64), *y)
    }
    #[allow(unused_imports)]
    use ark_ff::PrimeField as _;
}
