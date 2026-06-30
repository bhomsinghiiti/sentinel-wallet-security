// A realistic sample wallet used for the offline demo and tests. Mirrors the
// kind of mess a real active wallet accumulates: a malicious 7702 delegation,
// phishing approvals, forgotten unlimited grants, and a couple of healthy ones.

import type { Approval } from "../core/types.ts";

export const SAMPLE_ADDRESS = "0x9C8f1a2B3c4D5e6F7081920aBcDeF012345A31b0";

export const SAMPLE_APPROVALS: Approval[] = [
  {
    kind: "delegation",
    asset: "ACCOUNT",
    spender: {
      address: "0x3d4700000000000000000000000000000000002f",
      label: "CrimeEnjoyor sweeper",
      verified: false,
      flagged: true,
      knownDrainer: true,
    },
    unlimited: true,
    allowance: "Account delegated (EIP-7702)",
    lastUsedDaysAgo: 4,
    exposureUsd: 48200,
  },
  {
    kind: "erc20-permit",
    asset: "USDC",
    spender: {
      address: "0x91b2000000000000000000000000000000007ae0",
      label: "Fake Permit2 (phishing)",
      verified: false,
      flagged: true,
      knownDrainer: true,
    },
    unlimited: true,
    allowance: "Unlimited",
    lastUsedDaysAgo: 2,
    exposureUsd: 31904,
  },
  {
    kind: "nft",
    asset: "BAYC",
    spender: {
      address: "0x7d3f0000000000000000000000000000000011cc",
      label: "Unverified marketplace",
      verified: false,
      flagged: false,
      knownDrainer: false,
    },
    unlimited: true,
    allowance: "ALL NFTs",
    lastUsedDaysAgo: 38,
    exposureUsd: 9800,
  },
  {
    kind: "erc20",
    asset: "WETH",
    spender: {
      address: "0x4ae10000000000000000000000000000000090bd",
      label: undefined,
      verified: false,
      flagged: false,
      knownDrainer: false,
    },
    unlimited: true,
    allowance: "Unlimited",
    lastUsedDaysAgo: 412,
    exposureUsd: 6500,
  },
  {
    kind: "erc20",
    asset: "USDT",
    spender: {
      address: "0x11110000000000000000000000000000000a1c84",
      label: "1inch Router v5",
      verified: true,
      flagged: false,
      knownDrainer: false,
    },
    unlimited: true,
    allowance: "Unlimited",
    lastUsedDaysAgo: 6,
    exposureUsd: 4100,
  },
  {
    kind: "erc20",
    asset: "LINK",
    spender: {
      address: "0x87870000000000000000000000000000000a9df2",
      label: "Aave v3 Pool",
      verified: true,
      flagged: false,
      knownDrainer: false,
    },
    unlimited: false,
    allowance: "50,000 LINK",
    lastUsedDaysAgo: 210,
    exposureUsd: 900,
  },
  {
    kind: "erc20",
    asset: "wstETH",
    spender: {
      address: "0x889e000000000000000000000000000000a043be",
      label: "Lido Withdrawal",
      verified: true,
      flagged: false,
      knownDrainer: false,
    },
    unlimited: false,
    allowance: "8.4 wstETH",
    lastUsedDaysAgo: 3,
    exposureUsd: 0,
  },
];
