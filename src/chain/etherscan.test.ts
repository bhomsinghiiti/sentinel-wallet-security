import { test } from "node:test";
import assert from "node:assert/strict";
import { isPermit2, PERMIT2_ADDRESS, TOPIC_APPROVAL, TOPIC_APPROVAL_FOR_ALL } from "./etherscan.ts";

test("event topic hashes are the canonical ones", () => {
  // Locked-in constants — a regression here silently breaks all discovery.
  assert.equal(TOPIC_APPROVAL, "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925");
  assert.equal(TOPIC_APPROVAL_FOR_ALL, "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31");
});

test("Permit2 address detection is case-insensitive", () => {
  assert.equal(isPermit2(PERMIT2_ADDRESS), true);
  assert.equal(isPermit2(PERMIT2_ADDRESS.toUpperCase().replace("0X", "0x")), true);
  assert.equal(isPermit2("0x1111111111111111111111111111111111111111"), false);
});

test("Permit2 canonical address is the known deterministic one", () => {
  assert.equal(PERMIT2_ADDRESS, "0x000000000022d473030f116ddee9f6b43ac78ba3");
});
