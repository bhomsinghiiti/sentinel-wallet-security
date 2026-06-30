// Sentinel core domain types — the shapes the risk engine reasons over.
// Deliberately adapter-neutral: a "scanner" (live RPC, or a fixture) produces
// these, and the pure risk engine turns them into findings. No chain/lib types leak in here.

export type RiskLevel = "critical" | "high" | "medium" | "low" | "safe";

export type ApprovalKind =
  | "erc20" // a normal ERC-20 allowance
  | "erc20-permit" // allowance granted via an off-chain Permit/Permit2 signature
  | "nft" // setApprovalForAll over a whole NFT collection
  | "delegation"; // an EIP-7702 account-level delegation (the new attack surface)

/** What a scanner knows about the contract a user has granted power to. */
export interface Spender {
  address: string;
  /** Human label if we recognize it (e.g. "Uniswap UniversalRouter"). */
  label?: string;
  /** Source-verified / reputable contract (Etherscan-verified + known protocol). */
  verified: boolean;
  /** On a curated risk/blocklist (phishing, scam) — elevated suspicion. */
  flagged: boolean;
  /** Matches a known wallet-drainer cluster — the worst case. */
  knownDrainer: boolean;
  /** This spender is the Permit2 universal-approval contract — has a hidden
   *  second layer of per-dApp allowances a plain ERC-20 scan can't see. */
  permit2?: boolean;
}

/** A single thing in a wallet that can move funds: an approval or a 7702 delegation. */
export interface Approval {
  kind: ApprovalKind;
  /** Token symbol for approvals, or "ACCOUNT" for a 7702 delegation. */
  asset: string;
  /** The token / collection contract address (the target of a revoke tx). */
  token: string;
  spender: Spender;
  /** True when the allowance is the max uint256 ("Unlimited"). */
  unlimited: boolean;
  /** Human-readable allowance, e.g. "Unlimited", "50,000 LINK", "ALL NFTs". */
  allowance: string;
  /** Days since this approval was last used on-chain; null if never/unknown. */
  lastUsedDaysAgo: number | null;
  /** Best-effort USD exposed if this approval were fully drained. */
  exposureUsd: number;
  /** The approved token itself is a honeypot/scam token (GoPlus). */
  honeypot?: boolean;
}

/** The engine's verdict on one approval. */
export interface Finding {
  approval: Approval;
  level: RiskLevel;
  /** Plain-language reason — shown to the user, never a raw code. */
  reason: string;
  /** Stable machine code for the rule that fired (testing/telemetry). */
  rule: string;
}

export type RiskBand = "CRITICAL" | "HIGH" | "ELEVATED" | "LOW";

export interface WalletReport {
  address: string;
  /** 0–100 composite risk score. */
  score: number;
  band: RiskBand;
  /** Sum of exposure across critical + high findings. */
  atRiskUsd: number;
  counts: Record<RiskLevel, number>;
  /** Findings, sorted worst-first. */
  findings: Finding[];
  /** Set when the account itself is delegated via EIP-7702. */
  delegation?: DelegationStatus;
}

export interface DelegationStatus {
  /** Whether the EOA currently delegates its code (EIP-7702). */
  delegated: boolean;
  /** The contract the account is delegated to, if any. */
  delegate?: string;
  /** Label if the delegate is recognized. */
  delegateLabel?: string;
  /** True if the delegate matches a known sweeper/drainer. */
  malicious: boolean;
}
