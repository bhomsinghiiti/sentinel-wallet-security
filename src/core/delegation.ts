// EIP-7702 delegation detection — Sentinel's wedge.
//
// Post-Pectra, an EOA can delegate its code to a contract. On-chain, a delegated
// account's code is exactly: 0xef0100 || <20-byte delegate address> (23 bytes).
// That makes detection a pure string parse of `eth_getCode` output — no library,
// no heuristics. This is the gap revoke.cash structurally can't address.

import type { DelegationStatus } from "./types.ts";

/** The EIP-7702 designator prefix that marks delegated account code. */
const DELEGATION_PREFIX = "0xef0100";

/**
 * A tiny curated list of delegate contracts. In production this is sourced from
 * threat feeds (Scam Sniffer, on-chain clustering); here it's a seed used to
 * demonstrate flagging. Addresses are compared lowercased.
 */
export interface DelegateIntel {
  /** address -> label, contracts we recognize as malicious sweepers. */
  knownSweepers: Record<string, string>;
  /** address -> label, contracts we recognize as legitimate (e.g. wallet vendors). */
  knownGood: Record<string, string>;
}

export const DEFAULT_INTEL: DelegateIntel = {
  // Seed entry representing the "CrimeEnjoyor"-class sweeper family (placeholder
  // address; real deployment pulls the live set). 97%+ of in-the-wild 7702
  // delegations have pointed at sweepers like this post-Pectra.
  knownSweepers: {
    "0x3d4700000000000000000000000000000000002f": "CrimeEnjoyor sweeper",
  },
  knownGood: {},
};

/**
 * Parse `eth_getCode` output into a delegation status. Pure + total.
 * @param code hex string returned by eth_getCode for the account
 */
export function detectDelegation(
  code: string | null | undefined,
  intel: DelegateIntel = DEFAULT_INTEL,
): DelegationStatus {
  const c = (code ?? "").toLowerCase();

  // A plain EOA has no code ("0x" or empty); a normal contract has code that
  // does NOT start with the 7702 designator.
  if (!c.startsWith(DELEGATION_PREFIX)) {
    return { delegated: false, malicious: false };
  }

  // Designator (0x + ef0100 = 8 chars) followed by a 20-byte (40-char) address.
  const hexBody = c.slice(DELEGATION_PREFIX.length);
  if (hexBody.length < 40) {
    // Malformed/short — treat as a delegation we can't resolve, flag for caution.
    return { delegated: true, malicious: false };
  }
  const delegate = "0x" + hexBody.slice(0, 40);

  const sweeperLabel = intel.knownSweepers[delegate];
  if (sweeperLabel) {
    return {
      delegated: true,
      delegate,
      delegateLabel: sweeperLabel,
      malicious: true,
    };
  }
  const goodLabel = intel.knownGood[delegate];
  return {
    delegated: true,
    delegate,
    delegateLabel: goodLabel,
    malicious: false,
  };
}
