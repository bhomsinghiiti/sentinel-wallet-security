import { test } from "node:test";
import assert from "node:assert/strict";
import { classifyApproval, scoreWallet } from "./risk.ts";
import type { Approval } from "./types.ts";

function appr(over: Partial<Approval> = {}): Approval {
  return {
    kind: "erc20",
    asset: "USDC",
    token: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
    spender: { address: "0xabc", verified: true, flagged: false, knownDrainer: false },
    unlimited: false,
    allowance: "100 USDC",
    lastUsedDaysAgo: 1,
    exposureUsd: 100,
    ...over,
  };
}

// --- CONFIRMED danger → CRITICAL ---
test("known drainer spender → critical", () => {
  const f = classifyApproval(appr({ spender: { address: "0x1", verified: false, flagged: true, knownDrainer: true } }));
  assert.equal(f.level, "critical");
  assert.equal(f.rule, "spender.drainer");
});

test("flagged spender (even if verified flag set) → critical", () => {
  const f = classifyApproval(appr({ spender: { address: "0x1", verified: true, flagged: true, knownDrainer: false } }));
  assert.equal(f.level, "critical");
  assert.equal(f.rule, "spender.flagged");
});

test("honeypot token → critical", () => {
  const f = classifyApproval(appr({ honeypot: true }));
  assert.equal(f.level, "critical");
  assert.equal(f.rule, "token.honeypot");
});

test("malicious 7702 delegation → critical with reset guidance", () => {
  const f = classifyApproval(appr({ kind: "delegation", asset: "ACCOUNT", spender: { address: "0x1", verified: false, flagged: true, knownDrainer: true } }));
  assert.equal(f.level, "critical");
  assert.equal(f.rule, "deleg.malicious");
  assert.match(f.reason, /zero address/);
});

// --- UNKNOWN / unverified → HIGH (no longer CRITICAL — the cry-wolf fix) ---
test("unknown 7702 delegation → high", () => {
  const f = classifyApproval(appr({ kind: "delegation", asset: "ACCOUNT", spender: { address: "0x1", verified: false, flagged: false, knownDrainer: false } }));
  assert.equal(f.level, "high");
});

test("unlimited allowance to UNVERIFIED contract → high (not critical)", () => {
  const f = classifyApproval(appr({ unlimited: true, spender: { address: "0x1", verified: false, flagged: false, knownDrainer: false } }));
  assert.equal(f.level, "high");
  assert.equal(f.rule, "allowance.unlimited.unverified");
});

test("NFT setApprovalForAll to unverified → high", () => {
  const f = classifyApproval(appr({ kind: "nft", asset: "BAYC", unlimited: true, spender: { address: "0x1", verified: false, flagged: false, knownDrainer: false } }));
  assert.equal(f.level, "high");
  assert.equal(f.rule, "nft.approveAll.unverified");
});

// --- KNOWN / trusted protocol → MEDIUM (routine; this is what stops crying wolf) ---
test("unlimited allowance to VERIFIED protocol → medium", () => {
  const f = classifyApproval(appr({ unlimited: true, spender: { address: "0x1", label: "Uniswap: Universal Router", verified: true, flagged: false, knownDrainer: false } }));
  assert.equal(f.level, "medium");
  assert.equal(f.rule, "allowance.unlimited.verified");
});

test("NFT approveAll to verified marketplace → medium", () => {
  const f = classifyApproval(appr({ kind: "nft", asset: "BAYC", unlimited: true, spender: { address: "0x1", label: "OpenSea", verified: true, flagged: false, knownDrainer: false } }));
  assert.equal(f.level, "medium");
  assert.equal(f.rule, "nft.approveAll.verified");
});

test("Permit2 spender (unlimited) → high", () => {
  const f = classifyApproval(appr({ unlimited: true, spender: { address: "0x000000000022d473030f116ddee9f6b43ac78ba3", verified: true, flagged: false, knownDrainer: false, permit2: true } }));
  assert.equal(f.rule, "spender.permit2");
  assert.equal(f.level, "high");
});

test("bounded + stale (>180d) → medium", () => {
  const f = classifyApproval(appr({ unlimited: false, lastUsedDaysAgo: 200, spender: { address: "0x1", verified: true, flagged: false, knownDrainer: false } }));
  assert.equal(f.level, "medium");
});

test("bounded + recent + verified → low", () => {
  const f = classifyApproval(appr({ unlimited: false, lastUsedDaysAgo: 2, spender: { address: "0x1", verified: true, flagged: false, knownDrainer: false } }));
  assert.equal(f.level, "low");
});

// --- scoreWallet ---
test("band is driven by the worst finding, not the sum (many mediums ≠ CRITICAL)", () => {
  const manyMediums = Array.from({ length: 20 }, () =>
    appr({ unlimited: true, spender: { address: "0x1", label: "Uniswap", verified: true, flagged: false, knownDrainer: false } }),
  );
  const r = scoreWallet("0xW", manyMediums);
  assert.equal(r.counts.medium, 20);
  assert.equal(r.band, "ELEVATED", "20 routine mediums should be ELEVATED, never CRITICAL");
});

test("one confirmed drainer → CRITICAL band", () => {
  const r = scoreWallet("0xW", [appr({ spender: { address: "0x2", verified: false, flagged: false, knownDrainer: true } })]);
  assert.equal(r.band, "CRITICAL");
  assert.equal(r.findings[0].level, "critical");
});

test("malicious delegation forces CRITICAL band even with no approvals", () => {
  const r = scoreWallet("0xW", [], { delegated: true, delegate: "0xbad", malicious: true });
  assert.equal(r.band, "CRITICAL");
  assert.ok(r.score >= 95);
});

test("atRiskUsd sums only critical + high exposure", () => {
  const r = scoreWallet("0xW", [
    appr({ spender: { address: "0x1", verified: false, flagged: false, knownDrainer: true }, exposureUsd: 1000 }), // critical
    appr({ unlimited: false, lastUsedDaysAgo: 2, spender: { address: "0x2", verified: true, flagged: false, knownDrainer: false }, exposureUsd: 500 }), // low
  ]);
  assert.equal(r.atRiskUsd, 1000);
});
