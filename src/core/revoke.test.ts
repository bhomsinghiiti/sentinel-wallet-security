import { test } from "node:test";
import assert from "node:assert/strict";
import { buildRevoke } from "./revoke.ts";
import type { Approval } from "./types.ts";

function appr(over: Partial<Approval> = {}): Approval {
  return {
    kind: "erc20",
    asset: "USDC",
    token: "0xA0b86991c6218b36c1D19D4a2e9Eb0cE3606eB48",
    spender: { address: "0x1111111254eeb25477b68fb85ed929f73a960582", verified: true, flagged: false, knownDrainer: false },
    unlimited: true,
    allowance: "Unlimited",
    lastUsedDaysAgo: null,
    exposureUsd: 0,
    ...over,
  };
}

test("ERC-20 revoke → approve(spender,0) calldata", () => {
  const tx = buildRevoke(appr());
  assert.ok(tx);
  assert.equal(tx.to, "0xA0b86991c6218b36c1D19D4a2e9Eb0cE3606eB48");
  // selector + 32-byte spender + 32-byte zero amount
  assert.equal(tx.data, "0x095ea7b3" + "0000000000000000000000001111111254eeb25477b68fb85ed929f73a960582" + "0".repeat(64));
});

test("NFT revoke → setApprovalForAll(operator,false) calldata", () => {
  const tx = buildRevoke(appr({ kind: "nft", asset: "BAYC", token: "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d", spender: { address: "0x7d3f0000000000000000000000000000000011cc", verified: false, flagged: false, knownDrainer: false } }));
  assert.ok(tx);
  assert.ok(tx.data.startsWith("0xa22cb465"));
  assert.ok(tx.data.endsWith("0".repeat(64))); // false
});

test("EIP-7702 delegation → null (must be revoked in-wallet)", () => {
  assert.equal(buildRevoke(appr({ kind: "delegation", asset: "ACCOUNT", token: "0x0000000000000000000000000000000000000000" })), null);
});

test("missing/invalid token → null", () => {
  assert.equal(buildRevoke(appr({ token: "" })), null);
  assert.equal(buildRevoke(appr({ token: "not-an-address" })), null);
});
