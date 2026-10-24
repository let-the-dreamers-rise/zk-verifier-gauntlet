# Finding F1 (live-exploited): a shipping PolkaVM Groth16 verifier SDK generates universally-forgeable verifiers

**Severity:** critical (soundness — anyone can mint a valid proof for any statement).
**Status:** responsibly disclosed to the SDK's authors ahead of publication. Vendor
name, repository, and the deployed contract address are withheld here until disclosure
is acknowledged; they are available to the curators privately on request.

## Root cause
The SDK's compile step runs:

    snarkjs groth16 setup <r1cs> <ptau> circuit_final.zkey
    snarkjs zkey export solidityverifier circuit_final.zkey verifier.sol

with **no `snarkjs zkey contribute`** (phase-2 contribution). snarkjs' bare
`groth16 setup` output is the *initial* key, whose delta is the G2 generator
(scalar 1) and whose toxic waste is public; snarkjs prints a "not safe for production"
warning the "one command / no crypto knowledge" UX hides. Confirmed on the SDK's
default ptau: `vk_delta_2 == vk_gamma_2 == G2 generator`.

## Exploit (delta == gamma == generator => universal forgery)
Groth16 check: e(-A,B)·e(alpha,beta)·e(vk_x,gamma)·e(C,delta) == 1, where
vk_x = IC[0] + Σ pub_i·IC[i]. With gamma == delta, choose:
  A := alpha,  B := beta,  C := -vk_x(chosen public inputs)
Then e(-alpha,beta)·e(alpha,beta)=1 and e(vk_x,gamma)·e(-vk_x,gamma)=1 for ANY
public inputs. No witness, no proving-key secret needed. This is the FoomCash
($2.26M, Feb 2026) bug class.

## Demonstration (reproducible, this repo)
`examples/zkama-forgery/run.sh` reproduces the SDK pipeline on a toy circuit whose
single public output is forced to 1, forges a proof asserting output = 7, and shows a
verifier compiled from that key accepting it on both the PolkaVM runtime (revive
dev-node) and an EVM reference. Controls: a random proof -> reject; the forged proof
with one bit flipped -> reject. So the verifier is not degenerate; it accepts
specifically the forgery.

## What the gauntlet does about it
- `gauntlet lint` flags `delta == gamma` / `delta == generator` before deployment,
  in milliseconds, no proving needed.
- `gauntlet forge` constructs the universal forgery and the on-chain differential
  re-confirms it on both VMs — turning "theoretically unsafe" into a pass/fail the
  curators can replay on-chain.
