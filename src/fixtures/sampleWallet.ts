// A realistic sample wallet used for the offline demo and tests. Mirrors the
// kind of mess a real active wallet accumulates: a malicious 7702 delegation,
// phishing approvals, forgotten unlimited grants, and a couple of healthy ones.

import type { Approval } from "../core/types.ts";

export const SAMPLE_ADDRESS = "0x9C8f1a2B3c4D5e6F7081920aBcDeF012345A31b0";

export const SAMPLE_APPROVALS: Approval[] = [
  {
    kind: "delegation",
    asset: "ACCOUNT",
    token: "0x0000000000000000000000000000000000000000",
    spender: { address: "0x3d4700000000000000000000000000000000002f", label: "CrimeEnjoyor sweeper", verified: false, flagged: true, knownDrainer: true },
    unlimited: true,
    allowance: "Account delegated (EIP-7702)",
    lastUsedDaysAgo: 4,
    exposureUsd: 48200,
  },
  {
    kind: "erc20-permit",
    asset: "USDC",
    token: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
    spender: { address: "0x91b2000000000000000000000000000000007ae0", label: "Fake Permit2 (phishing)", verified: false, flagged: true, knownDrainer: true },
    unlimited: true,
    allowance: "Unlimited",
    lastUsedDaysAgo: 2,
    exposureUsd: 31904,
  },
  {
    kind: "nft",
    asset: "BAYC",
    token: "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d",
    spender: { address: "0x7d3f0000000000000000000000000000000011cc", label: "Unverified marketplace", verified: false, flagged: false, knownDrainer: false },
    unlimited: true,
    allowance: "ALL NFTs",
    lastUsedDaysAgo: 38,
    exposureUsd: 9800,
  },
  {
    kind: "erc20",
    asset: "WETH",
    token: "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
    spender: { address: "0x4ae10000000000000000000000000000000090bd", label: undefined, verified: false, flagged: false, knownDrainer: false },
    unlimited: true,
    allowance: "Unlimited",
    lastUsedDaysAgo: 412,
    exposureUsd: 6500,
  },
  {
    kind: "erc20",
    asset: "USDT",
    token: "0xdac17f958d2ee523a2206206994597c13d831ec7",
    spender: { address: "0x1111111254eeb25477b68fb85ed929f73a960582", label: "1inch Router v5", verified: true, flagged: false, knownDrainer: false },
    unlimited: true,
    allowance: "Unlimited",
    lastUsedDaysAgo: 6,
    exposureUsd: 4100,
  },
  {
    kind: "erc20",
    asset: "LINK",
    token: "0x514910771af9ca656af840dff83e8264ecf986ca",
    spender: { address: "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2", label: "Aave v3 Pool", verified: true, flagged: false, knownDrainer: false },
    unlimited: false,
    allowance: "50,000 LINK",
    lastUsedDaysAgo: 210,
    exposureUsd: 900,
  },
  {
    kind: "erc20",
    asset: "wstETH",
    token: "0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0",
    spender: { address: "0x889edc2edab5f40e902b864ad4d7ade8e412f9b1", label: "Lido Withdrawal", verified: true, flagged: false, knownDrainer: false },
    unlimited: false,
    allowance: "8.4 wstETH",
    lastUsedDaysAgo: 3,
    exposureUsd: 0,
  },
];
