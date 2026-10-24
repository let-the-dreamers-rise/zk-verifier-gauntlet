# zk-verifier-gauntlet

A soundness harness for the ZK proof verifiers arriving on Polkadot Hub /
PolkaVM (pallet-revive). It attacks a verifier the way a thief would, rather
than testing that it accepts honest proofs, and it does so on the real runtime,
not an abstraction of it.

Privacy on Kusama rests entirely on these verifiers being *sound*: a verifier
that can be made to accept a proof of a false statement turns a shielded pool,
an age gate, a private vote or a proof-of-personhood into a forgery machine. The
Kusama ZK bounty is funding verifiers faster than anyone is adversarially
testing them — ZK Email's generated Groth16 contracts, the ZKAMA SDK, a
Noir→PolkaVM UltraHonk generator, a post-quantum STARK spike — and verifier
soundness bugs have a track record of costing real money (FoomCash, $2.26M, a
`delta == gamma` trusted-setup flaw; Aleo's Fiat-Shamir proof forgery).

The gauntlet is the shared, reusable soundness layer those verifiers plug into.

## What it does today (milestone 1, Groth16 / BN254)

1. **Static VK lints** — `gauntlet lint verification_key.json`. No proving
   needed; runs in milliseconds in CI. Catches the whole malformed-trusted-setup
   class:
   - every curve point on-curve **and** in the prime-order subgroup
     (off-subgroup points are a malleability vector),
   - no structural element is the identity,
   - `IC` length matches `nPublic`,
   - **`delta_2 != gamma_2`** and **`delta_2 != G2 generator`** — the forgery
     flaws. In a snarkjs key `gamma_2` is fixed to the generator and only
     `delta_2` is randomised by the phase-2 contribution, so these two
     conditions detect a trusted setup that was never contributed to.

2. **Universal forgery constructor** — `gauntlet forge verification_key.json
   <pub0> [pub1 ...]`. When a VK has `delta == gamma`, it builds a proof for
   *arbitrary* public inputs with no witness and no proving key, confirms it
   against a reference pairing check, and prints the exact
   `verifyProof(a, b, c, pub)` tuple a snarkjs-generated Solidity verifier
   expects. This turns "theoretically unsafe" into a proof the curators can
   replay on-chain.

3. **PolkaVM ↔ EVM differential** (`differential/battery.mjs`) — deploys the
   same verifier to a `pallet-revive` node and to an EVM, runs a battery of
   adversarial vectors (off-curve points, infinity encodings, public inputs ≥
   the field modulus, coordinate wraps `+Q`, point negation) against both, and
   asserts they agree on every one. Divergence is a PolkaVM-porting bug in the
   verifier (e.g. a BN254-precompile edge case handled differently by
   `substrate-bn` than by the EVM). Agreement on the forgery vector proves the
   forgery is a real soundness flaw, not a VM artefact.

## The finding that motivated this

`examples/zkama-forgery/run.sh` reproduces, from an empty circuit, the exact
pipeline of **ZKAMA / `zk-polka-sdk`** — the AssetHub-hackathon-winning SDK that
applied to this bounty for $49,440. Its `lib/compile.js` runs `snarkjs groth16
setup` and never runs `snarkjs zkey contribute`, so every verifier it generates
has `delta == gamma == G2 generator`. The script forges a proof asserting
`isAdult = 7` and shows a verifier built from that key — running on the real
PolkaVM runtime and on an EVM — accepting it. The grantee's own demo deploys
exactly this key to Polkadot Asset Hub.

See [`FINDINGS.md`](./FINDINGS.md).

## Usage

```bash
cargo build --release
./target/release/gauntlet lint  fixtures/forgeable_vk.json   # exit 1, UNSOUND
./target/release/gauntlet lint  fixtures/honest_vk.json      # exit 0
./target/release/gauntlet forge fixtures/forgeable_vk.json 7 # forged tuple + reference_verify:true
```

The two fixtures are a real snarkjs key straight from `groth16 setup`
(`forgeable_vk.json`) and the same key after a phase-2 `zkey contribute`
(`honest_vk.json`), so the test suite proves both a true positive and the
absence of a false positive.

## Toolchain pins (validated in CI)

- `pallet-revive` only accepts `ReviveV1`-tagged blobs. **resolc 0.5.0** is the
  resolc that produces accepted blobs against the current `revive` dev-node;
  resolc 1.x emits blobs rejected as `CodeRejected`. This pin is a finding in
  its own right and the harness documents it so downstream builders don't lose
  a day to it.
- circom 2.2.2, snarkjs 0.7.5, solc 0.8.30, foundry 1.4.0, dev-node + eth-rpc
  from `paritytech/hardhat-polkadot` (`nodes-latest`).

## Roadmap

- **M1 (this repo):** Groth16/BN254 lints + forgery + PolkaVM↔EVM differential,
  run against ZK Email's and ZKAMA's generated verifiers.
- **M2:** PLONK and UltraHonk adapters (Barretenberg/Noir, targeting
  `zkemail/polkavm-noir-verifier`), Fiat-Shamir transcript-binding tests
  (replay a recorded challenge, mutate one claim, assert rejection), and the
  STARK adapter (trailing-byte / out-of-range / prover-chosen-trace mutations
  that `pq-stark-polkavm`'s own README lists as open gaps).
- **M3:** a reusable GitHub Action so any verifier repo gets the lints and the
  differential on every PR, plus a published soundness report on three live
  Kusama verifiers.

## License

Apache-2.0. Open source, per the bounty's open-source mandate.
