// Sentinel risk engine — the product's brain, and intentionally pure (no I/O).
//
// This is the part the research said a human must own: the rules that decide what
// "risky" means. Everything here is deterministic and unit-tested. A scanner feeds
// it Approvals; it returns Findings + a WalletReport. Swapping the data source
// (live RPC, fixture, future indexer) never touches these rules.

import type {
  Approval,
  Finding,
  RiskLevel,
  WalletReport,
  RiskBand,
  DelegationStatus,
} from "./types.ts";

const STALE_DAYS = 365; // an approval unused for a year is a forgotten liability
const STALE_SOFT_DAYS = 180;

const LEVEL_WEIGHT: Record<RiskLevel, number> = {
  critical: 40,
  high: 15,
  medium: 5,
  low: 1,
  safe: 0,
};

/**
 * Classify a single approval. Order matters: the worst applicable rule wins.
 * Rules are deliberately conservative and explainable — we present risk SIGNALS,
 * not verdicts, and never claim something is "safe" we can't justify.
 */
export function classifyApproval(a: Approval): Finding {
  const f = (level: RiskLevel, rule: string, reason: string): Finding => ({
    approval: a,
    level,
    rule,
    reason,
  });

  // 1. EIP-7702 account delegation to a known sweeper — the highest danger.
  if (a.kind === "delegation") {
    if (a.spender.knownDrainer || a.spender.flagged) {
      return f(
        "critical",
        "deleg.malicious",
        "Your account is delegated to a known sweeper. Any funds that arrive can be auto-forwarded to an attacker with no further signature. Most tools can't remove this — reset the delegation to the zero address.",
      );
    }
    return f(
      "high",
      "deleg.unknown",
      "Your account delegates its code via EIP-7702 to a contract we don't recognize. Confirm you set this intentionally; if not, reset it.",
    );
  }

  // 2. Any approval to a known drainer cluster.
  if (a.spender.knownDrainer) {
    return f(
      "critical",
      "spender.drainer",
      `The spender matches a known wallet-drainer cluster. Your ${a.asset} can be taken at any moment — revoke now.`,
    );
  }

  // 3. NFT collection-wide approval to an unverified / flagged contract.
  if (a.kind === "nft" && (!a.spender.verified || a.spender.flagged)) {
    return f(
      "critical",
      "nft.approveAll.unverified",
      `setApprovalForAll grants control of your ENTIRE ${a.asset} collection to an unverified contract — the most common NFT-theft vector. Revoke it.`,
    );
  }

  // 4. Flagged spender (on a risk/blocklist) holding any allowance.
  if (a.spender.flagged) {
    return f(
      "critical",
      "spender.flagged",
      `This spender is on a risk/blocklist (phishing or scam). Revoke its access to your ${a.asset}.`,
    );
  }

  // 4b. Approval to the Permit2 universal-approval contract — surface the hidden
  //     second layer (per-dApp allowances inside Permit2 a plain scan can't see).
  if (a.spender.permit2) {
    return f(
      a.unlimited ? "high" : "medium",
      "spender.permit2",
      `This approves Permit2 (the universal-approval contract). Permit2 can then hold its own per-app allowances that a normal scan doesn't show — review your Permit2 allowances separately, and cap this if you don't actively use Permit2-based apps.`,
    );
  }

  // 5. Unlimited allowance to an unverified contract.
  if (a.unlimited && !a.spender.verified) {
    return f(
      "critical",
      "allowance.unlimited.unverified",
      `Unlimited allowance to an unverified contract${
        isStale(a) ? `, untouched for ${a.lastUsedDaysAgo} days` : ""
      } — maximum exposure with no accountability. Revoke it.`,
    );
  }

  // 6. Unlimited allowance to a verified contract but forgotten (stale).
  if (a.unlimited && isStale(a)) {
    return f(
      "critical",
      "allowance.unlimited.stale",
      `Unlimited allowance unused for ${a.lastUsedDaysAgo} days — a forgotten approval sitting at full exposure. Clear it.`,
    );
  }

  // 7. Unlimited allowance to a verified, in-use contract — still worth capping.
  if (a.unlimited) {
    return f(
      "high",
      "allowance.unlimited.verified",
      `Unlimited allowance to ${
        a.spender.label ?? "a verified contract"
      }. Legitimate, but if that contract is ever exploited your whole balance is reachable — best practice is to cap it.`,
    );
  }

  // 8. Bounded allowance but stale to a trusted protocol.
  if ((a.lastUsedDaysAgo ?? 0) >= STALE_SOFT_DAYS) {
    return f(
      "medium",
      "allowance.bounded.stale",
      `A capped approval unused for ${a.lastUsedDaysAgo} days. Low urgency, but worth clearing.`,
    );
  }

  // 9. Bounded, recent, verified — healthy.
  if (a.spender.verified) {
    return f(
      "low",
      "allowance.healthy",
      `An exact-amount approval to ${
        a.spender.label ?? "a verified contract"
      }, used recently — a healthy approval.`,
    );
  }

  // 10. Bounded but unverified spender — mild caution.
  return f(
    "medium",
    "allowance.bounded.unverified",
    `A bounded approval to an unverified contract. Clear it if you no longer use it.`,
  );
}

function isStale(a: Approval): boolean {
  return (a.lastUsedDaysAgo ?? 0) >= STALE_DAYS;
}

const LEVEL_RANK: Record<RiskLevel, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  safe: 4,
};

/** Score a wallet from its approvals (+ optional delegation status). Pure. */
export function scoreWallet(
  address: string,
  approvals: Approval[],
  delegation?: DelegationStatus,
): WalletReport {
  const findings = approvals
    .map(classifyApproval)
    .sort(
      (a, b) =>
        LEVEL_RANK[a.level] - LEVEL_RANK[b.level] ||
        b.approval.exposureUsd - a.approval.exposureUsd,
    );

  const counts: Record<RiskLevel, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    safe: 0,
  };
  let weighted = 0;
  let atRiskUsd = 0;
  for (const f of findings) {
    counts[f.level]++;
    weighted += LEVEL_WEIGHT[f.level];
    if (f.level === "critical" || f.level === "high") {
      atRiskUsd += f.approval.exposureUsd;
    }
  }

  // Composite 0–100. A single critical alone should read as serious, so we
  // saturate rather than average — many small risks and one big risk both matter.
  let score = Math.min(100, weighted);

  // A malicious 7702 delegation is an account-takeover; force the ceiling.
  if (delegation?.malicious) score = Math.max(score, 95);

  const band: RiskBand =
    score >= 70 || delegation?.malicious
      ? "CRITICAL"
      : score >= 40
        ? "HIGH"
        : score >= 15
          ? "ELEVATED"
          : "LOW";

  return { address, score, band, atRiskUsd, counts, findings, delegation };
}
