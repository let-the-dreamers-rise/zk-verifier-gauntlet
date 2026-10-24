// Differential battery: submit a fixed set of adversarial vectors to the SAME
// Groth16 verifier deployed on a PolkaVM runtime (pallet-revive) and on an EVM,
// and assert the two agree on every vector. Divergence is a PolkaVM-porting
// bug in the verifier (e.g. a BN254 precompile edge case handled differently
// by substrate-bn vs the EVM), which is exactly the class the Kusama bounty's
// new verifiers are exposed to. Agreement on the forgery vector shows the
// forgery is not a VM artefact — both accept it.
//
// Usage: node battery.mjs <forged.json> <pvm_rpc> <pvm_addr> <evm_rpc> <evm_addr>

import fs from "fs";
import { ethers } from "ethers";

const [, , forgedPath, pvmRpc, pvmAddr, evmRpc, evmAddr] = process.argv;
const forged = JSON.parse(fs.readFileSync(forgedPath));
const Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583n; // Fq
const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n; // Fr

const abi = [
  "function verifyProof(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[1] pub) view returns (bool)",
];

const B = (x) => BigInt(x);
const base = {
  a: forged.pA.map(B),
  b: forged.pB.map((r) => r.map(B)),
  c: forged.pC.map(B),
  pub: forged.pubSignals.map(B),
};

// Each vector: a label plus a transform of the base (forged) call.
const vectors = [
  ["forgery (unchanged)", (v) => v],
  ["A.x += 1 (off curve)", (v) => ({ ...v, a: [v.a[0] + 1n, v.a[1]] })],
  ["A = infinity (0,0)", (v) => ({ ...v, a: [0n, 0n] })],
  ["C = infinity (0,0)", (v) => ({ ...v, c: [0n, 0n] })],
  ["pub += R (field wrap)", (v) => ({ ...v, pub: [v.pub[0] + R] })],
  ["A.x += Q (coord wrap)", (v) => ({ ...v, a: [v.a[0] + Q, v.a[1]] })],
  ["A.y negated mod Q", (v) => ({ ...v, a: [v.a[0], (Q - (v.a[1] % Q)) % Q] })],
];

async function run(rpc, addr) {
  const provider = new ethers.JsonRpcProvider(rpc);
  const c = new ethers.Contract(addr, abi, provider);
  const out = [];
  for (const [label, t] of vectors) {
    const v = t(base);
    try {
      const r = await c.verifyProof(v.a, v.b, v.c, v.pub);
      out.push([label, r ? "accept" : "reject"]);
    } catch (e) {
      out.push([label, "revert"]);
    }
  }
  return out;
}

const pvm = await run(pvmRpc, pvmAddr);
const evm = await run(evmRpc, evmAddr);

let diverged = 0;
console.log("vector".padEnd(26), "PolkaVM".padEnd(9), "EVM".padEnd(9), "agree");
for (let i = 0; i < vectors.length; i++) {
  const agree = pvm[i][1] === evm[i][1];
  if (!agree) diverged++;
  console.log(
    pvm[i][0].padEnd(26),
    pvm[i][1].padEnd(9),
    evm[i][1].padEnd(9),
    agree ? "yes" : "NO <-- divergence"
  );
}
console.log(`\n${diverged} divergence(s). forgery accepted on both: ${pvm[0][1] === "accept" && evm[0][1] === "accept"}`);
process.exit(diverged === 0 ? 0 : 1);
