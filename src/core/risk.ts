// Sentinel risk engine — pure (no I/O), deterministic, unit-tested.
//
// Philosophy (matching how real scanners avoid crying wolf): CRITICAL is reserved for
// CONFIRMED danger — a known drainer, a flagged/sanctioned spender, a honeypot token, a
// malicious account delegation. An unlimited approval to an UNKNOWN contract is HIGH (worth
// fixing, not confirmed bad); an unlimited approval to a KNOWN/trusted protocol is MEDIUM
// (routine, capping is best practice). The judgment data (verified/flagged/knownDrainer/
// honeypot) is supplied by the reputation + allowlist layer; this file only reasons over it.

import type { Approval, Finding, RiskLevel, WalletReport, RiskBand, DelegationStatus } from "./types.ts";

const STALE_DAYS = 365;
const STALE_SOFT_DAYS = 180;

const LEVEL_WEIGHT: Record<RiskLevel, number> = { critical: 40, high: 15, medium: 5, low: 1, safe: 0 };
const LEVEL_RANK: Record<RiskLevel, number> = { critical: 0, high: 1, medium: 2, low: 3, safe: 4 };

/** Classify a single approval. Worst applicable rule wins (top to bottom). */
export function classifyApproval(a: Approval): Finding {
  const f = (level: RiskLevel, rule: string, reason: string): Finding => ({ approval: a, level, rule, reason });
  const stale = (a.lastUsedDaysAgo ?? 0) >= STALE_DAYS;

  // 1. EIP-7702 account delegation.
  if (a.kind === "delegation") {
    if (a.spender.knownDrainer || a.spender.flagged) {
      return f("critical", "deleg.malicious",
        "Your account is delegated to a known sweeper. Any funds that arrive can be auto-forwarded to an attacker with no further signature. Reset the delegation to the zero address.");
    }
    return f("high", "deleg.unknown",
      "Your account delegates its code via EIP-7702 to a contract we don't recognize. Confirm you set this intentionally; if not, reset it.");
  }

  // 2. The token itself is a honeypot/scam token.
  if (a.honeypot) {
    return f("critical", "token.honeypot",
      `${a.asset} is flagged as a honeypot/scam token. Revoke this approval and avoid interacting with it.`);
  }

  // 3. Spender is a known drainer cluster.
  if (a.spender.knownDrainer) {
    return f("critical", "spender.drainer",
      `The spender is a known wallet drainer${a.spender.label ? ` (${a.spender.label})` : ""}. Your ${a.asset} can be taken at any moment — revoke now.`);
  }

  // 4. Spender is flagged (scam/phishing/sanctioned blocklist).
  if (a.spender.flagged) {
    return f("critical", "spender.flagged",
      `This spender is flagged${a.spender.label ? ` (${a.spender.label})` : ""}. Revoke its access to your ${a.asset}.`);
  }

  // 5. Permit2 universal-approval layer. This is the STANDARD Uniswap setup, so it's
  //    routine (MEDIUM) — the real exposure is the per-app allowances Permit2 holds
  //    internally, which a normal approval scan can't see (enumeration is on the roadmap).
  if (a.spender.permit2) {
    return f("medium", "spender.permit2",
      `Routine Uniswap/Permit2 approval. The real risk isn't this grant — it's the per-app allowances Permit2 holds internally (which a normal scan can't see yet). Safe to keep if you use Uniswap; revoke if you don't.`);
  }

  // 6. NFT collection-wide approval.
  if (a.kind === "nft") {
    if (a.spender.verified) {
      return f("medium", "nft.approveAll.verified",
        `Collection-wide approval to ${a.spender.label ?? "a known marketplace"}. Legitimate, but it covers your ENTIRE ${a.asset} collection — revoke if you no longer use it.`);
    }
    return f("high", "nft.approveAll.unverified",
      `setApprovalForAll grants control of your ENTIRE ${a.asset} collection to an unverified contract — a common NFT-theft vector. Revoke if unexpected.`);
  }

  // 7. Unlimited ERC-20 allowance.
  if (a.unlimited) {
    if (!a.spender.verified) {
      // Gate HIGH on real value at stake — a $0 dust token to an unknown contract is
      // low-priority noise, not a top threat.
      if (a.exposureUsd > 0) {
        return f("high", "allowance.unlimited.unverified",
          `Unlimited allowance to an unverified contract${stale ? `, untouched for ${a.lastUsedDaysAgo} days` : ""} — real funds exposed with no known identity. Revoke if you don't recognize it.`);
      }
      return f("low", "allowance.unlimited.unverified.dust",
        `Unlimited allowance to an unverified contract, but no balance is currently exposed. Low priority — clear it if you don't recognize it.`);
    }
    return f("medium", "allowance.unlimited.verified",
      `Unlimited allowance to ${a.spender.label ?? "a known protocol"}. Routine for DeFi, but capping it limits damage if that contract is ever exploited.`);
  }

  // 8. Bounded but stale.
  if ((a.lastUsedDaysAgo ?? 0) >= STALE_SOFT_DAYS) {
    return f("medium", "allowance.bounded.stale", `A capped approval unused for ${a.lastUsedDaysAgo} days. Low urgency, but worth clearing.`);
  }

  // 9. Bounded, recent, verified — healthy.
  if (a.spender.verified) {
    return f("low", "allowance.healthy", `An exact-amount approval to ${a.spender.label ?? "a verified contract"}, used recently — a healthy approval.`);
  }

  // 10. Bounded to an unverified spender — mild caution.
  return f("medium", "allowance.bounded.unverified", `A bounded approval to an unverified contract. Clear it if you no longer use it.`);
}

/** Score a wallet from its approvals (+ optional delegation status). Pure. */
export function scoreWallet(address: string, approvals: Approval[], delegation?: DelegationStatus): WalletReport {
  const findings = approvals
    .map(classifyApproval)
    .sort((a, b) => LEVEL_RANK[a.level] - LEVEL_RANK[b.level] || b.approval.exposureUsd - a.approval.exposureUsd);

  const counts: Record<RiskLevel, number> = { critical: 0, high: 0, medium: 0, low: 0, safe: 0 };
  let weighted = 0;
  let atRiskUsd = 0;
  for (const fnd of findings) {
    counts[fnd.level]++;
    weighted += LEVEL_WEIGHT[fnd.level];
    // Total exposure = everything an approval could move (incl. trusted protocols), so the
    // headline reflects real money (e.g. a large WETH→CoW grant), not just confirmed-bad rows.
    atRiskUsd += fnd.approval.exposureUsd;
  }

  let score = Math.min(100, weighted);
  if (delegation?.malicious) score = Math.max(score, 95);

  // Band is driven by the WORST confirmed finding, not the raw sum — so a wallet with
  // many routine (medium) approvals isn't screamed at as CRITICAL.
  const band: RiskBand =
    counts.critical > 0 || delegation?.malicious
      ? "CRITICAL"
      : counts.high > 0
        ? "HIGH"
        : counts.medium > 0
          ? "ELEVATED"
          : "LOW";

  return { address, score, band, atRiskUsd, counts, findings, delegation };
}
