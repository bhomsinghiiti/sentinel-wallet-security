import { test } from "node:test";
import assert from "node:assert/strict";
import { classifyApproval, scoreWallet } from "./risk.ts";
import type { Approval } from "./types.ts";

// Helper to build an approval with sensible defaults, overriding fields per test.
function appr(over: Partial<Approval> = {}): Approval {
  return {
    kind: "erc20",
    asset: "USDC",
    spender: { address: "0xabc", verified: true, flagged: false, knownDrainer: false },
    unlimited: false,
    allowance: "100 USDC",
    lastUsedDaysAgo: 1,
    exposureUsd: 100,
    ...over,
  };
}

test("known drainer spender → critical", () => {
  const f = classifyApproval(appr({ spender: { address: "0x1", verified: false, flagged: true, knownDrainer: true } }));
  assert.equal(f.level, "critical");
  assert.equal(f.rule, "spender.drainer");
});

test("malicious 7702 delegation → critical with reset guidance", () => {
  const f = classifyApproval(
    appr({ kind: "delegation", asset: "ACCOUNT", spender: { address: "0x1", verified: false, flagged: true, knownDrainer: true } }),
  );
  assert.equal(f.level, "critical");
  assert.equal(f.rule, "deleg.malicious");
  assert.match(f.reason, /zero address/);
});

test("unknown 7702 delegation → high (not critical)", () => {
  const f = classifyApproval(
    appr({ kind: "delegation", asset: "ACCOUNT", spender: { address: "0x1", verified: false, flagged: false, knownDrainer: false } }),
  );
  assert.equal(f.level, "high");
});

test("NFT setApprovalForAll to unverified → critical", () => {
  const f = classifyApproval(appr({ kind: "nft", asset: "BAYC", unlimited: true, spender: { address: "0x1", verified: false, flagged: false, knownDrainer: false } }));
  assert.equal(f.level, "critical");
  assert.equal(f.rule, "nft.approveAll.unverified");
});

test("unlimited allowance to unverified contract → critical", () => {
  const f = classifyApproval(appr({ unlimited: true, spender: { address: "0x1", verified: false, flagged: false, knownDrainer: false } }));
  assert.equal(f.level, "critical");
  assert.equal(f.rule, "allowance.unlimited.unverified");
});

test("unlimited allowance to verified but stale (>365d) → critical", () => {
  const f = classifyApproval(appr({ unlimited: true, lastUsedDaysAgo: 400, spender: { address: "0x1", verified: true, flagged: false, knownDrainer: false } }));
  assert.equal(f.level, "critical");
  assert.equal(f.rule, "allowance.unlimited.stale");
});

test("unlimited allowance to verified + recent → high", () => {
  const f = classifyApproval(appr({ unlimited: true, lastUsedDaysAgo: 5, spender: { address: "0x1", label: "1inch", verified: true, flagged: false, knownDrainer: false } }));
  assert.equal(f.level, "high");
  assert.equal(f.rule, "allowance.unlimited.verified");
});

test("bounded + stale (>180d) verified → medium", () => {
  const f = classifyApproval(appr({ unlimited: false, lastUsedDaysAgo: 200, spender: { address: "0x1", verified: true, flagged: false, knownDrainer: false } }));
  assert.equal(f.level, "medium");
});

test("bounded + recent + verified → low", () => {
  const f = classifyApproval(appr({ unlimited: false, lastUsedDaysAgo: 2, spender: { address: "0x1", verified: true, flagged: false, knownDrainer: false } }));
  assert.equal(f.level, "low");
});

test("flagged spender beats verified flag → critical", () => {
  const f = classifyApproval(appr({ spender: { address: "0x1", verified: true, flagged: true, knownDrainer: false } }));
  assert.equal(f.level, "critical");
  assert.equal(f.rule, "spender.flagged");
});

test("Permit2 spender → flagged as the hidden-allowance layer", () => {
  const f = classifyApproval(appr({ unlimited: true, spender: { address: "0x000000000022d473030f116ddee9f6b43ac78ba3", verified: true, flagged: false, knownDrainer: false, permit2: true } }));
  assert.equal(f.rule, "spender.permit2");
  assert.equal(f.level, "high");
  assert.match(f.reason, /Permit2/);
});

test("scoreWallet sorts worst-first and counts levels", () => {
  const r = scoreWallet("0xWALLET", [
    appr({ unlimited: false, lastUsedDaysAgo: 2, spender: { address: "0x1", verified: true, flagged: false, knownDrainer: false } }), // low
    appr({ spender: { address: "0x2", verified: false, flagged: false, knownDrainer: true } }), // critical
  ]);
  assert.equal(r.findings[0].level, "critical", "critical sorts first");
  assert.equal(r.counts.critical, 1);
  assert.equal(r.counts.low, 1);
  assert.ok(r.score >= 40, "a critical should push the score up");
});

test("malicious delegation forces CRITICAL band even with few approvals", () => {
  const r = scoreWallet("0xWALLET", [], { delegated: true, delegate: "0xbad", malicious: true });
  assert.equal(r.band, "CRITICAL");
  assert.ok(r.score >= 95);
});

test("atRiskUsd sums only critical + high exposure", () => {
  const r = scoreWallet("0xW", [
    appr({ spender: { address: "0x1", verified: false, flagged: false, knownDrainer: true }, exposureUsd: 1000 }), // critical
    appr({ unlimited: false, lastUsedDaysAgo: 2, spender: { address: "0x2", verified: true, flagged: false, knownDrainer: false }, exposureUsd: 500 }), // low — excluded
  ]);
  assert.equal(r.atRiskUsd, 1000);
});
