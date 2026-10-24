//! `gauntlet` CLI.
//!
//!   gauntlet lint  <verification_key.json>
//!       Run the static soundness lints. Exit 1 if any lint fails.
//!
//!   gauntlet forge <verification_key.json> <pub0> [pub1 ...]
//!       If the VK is exploitable (delta == gamma), construct a universal
//!       forgery for the given public inputs, print the snarkjs-Solidity
//!       `verifyProof` tuple as JSON, and confirm it against the reference
//!       pairing check. Exit 1 if the VK is not exploitable.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use gauntlet::{forge, verify, vk};
use num_bigint::BigUint;
use std::process::exit;

fn load(path: &str) -> vk::Vk {
    let s = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("cannot read {path}: {e}");
        exit(2);
    });
    let j: vk::SnarkjsVk = serde_json::from_str(&s).unwrap_or_else(|e| {
        eprintln!("cannot parse snarkjs vk: {e}");
        exit(2);
    });
    vk::Vk::from_snarkjs(&j).unwrap_or_else(|e| {
        eprintln!("vk error: {e}");
        exit(2);
    })
}

fn fr(s: &str) -> Fr {
    let n: BigUint = s.parse().unwrap_or_else(|_| {
        eprintln!("bad public input: {s}");
        exit(2);
    });
    Fr::from(n)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: gauntlet <lint|forge> <verification_key.json> [public inputs...]");
        exit(2);
    }
    let cmd = args[1].as_str();
    let v = load(&args[2]);

    match cmd {
        "lint" => {
            let lints = vk::lint(&v);
            let mut failed = false;
            for l in &lints {
                let tag = if l.ok {
                    "PASS"
                } else {
                    failed = true;
                    "FAIL"
                };
                println!("[{tag}] {:<22} {:?}  {}", l.id, l.severity, l.detail);
            }
            if failed {
                println!("\nVERDICT: verifier is UNSOUND — do not deploy.");
                exit(1);
            }
            println!("\nVERDICT: no soundness lint triggered.");
        }
        "forge" => {
            let public: Vec<Fr> = args[3..].iter().map(|s| fr(s)).collect();
            match forge::forge(&v, &public) {
                Ok(p) => {
                    // reference-verify before printing, so we never emit a dud
                    use ark_bn254::{Fq, Fq2, G1Affine, G2Affine};
                    let q = |s: &str| Fq::from(s.parse::<BigUint>().unwrap());
                    let a = G1Affine::new(q(&p.p_a[0]), q(&p.p_a[1]));
                    let b = G2Affine::new(
                        Fq2::new(q(&p.p_b[0][1]), q(&p.p_b[0][0])),
                        Fq2::new(q(&p.p_b[1][1]), q(&p.p_b[1][0])),
                    );
                    let c = G1Affine::new(q(&p.p_c[0]), q(&p.p_c[1]));
                    let ok = verify::groth16_verify(&v, a, b, c, &public).unwrap();
                    let json = serde_json::json!({
                        "pA": p.p_a,
                        "pB": p.p_b,
                        "pC": p.p_c,
                        "pubSignals": p.pub_signals,
                        "reference_verify": ok,
                    });
                    println!("{}", serde_json::to_string_pretty(&json).unwrap());
                    if !ok {
                        eprintln!("internal error: forged proof failed reference check");
                        exit(2);
                    }
                }
                Err(e) => {
                    eprintln!("not exploitable: {e}");
                    exit(1);
                }
            }
        }
        other => {
            eprintln!("unknown command: {other}");
            exit(2);
        }
    }
    let _ = Fr::MODULUS; // keep PrimeField import meaningful across cfgs
}
