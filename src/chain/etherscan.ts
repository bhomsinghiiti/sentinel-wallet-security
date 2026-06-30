// Etherscan v2 discovery — the reliable way to find ALL of a wallet's approval
// events across full history (what anonymous public RPCs refuse). One free key
// (chainid=1 still free as of 2026), held server-side, works for every user.
//
// This module only DISCOVERS candidate (token, spender) pairs from the event log.
// Current-allowance verification happens separately via cheap eth_call (rpc.ts) —
// because an event only says an approval *was set*, not that it's still live.

// keccak256("Approval(address,address,uint256)") — ERC-20 (also ERC-721 single-token)
export const TOPIC_APPROVAL = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925";
// keccak256("ApprovalForAll(address,address,bool)") — ERC-721 / ERC-1155
export const TOPIC_APPROVAL_FOR_ALL = "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31";

// Uniswap Permit2 — deterministic address on mainnet + most EVM chains.
export const PERMIT2_ADDRESS = "0x000000000022d473030f116ddee9f6b43ac78ba3";

const ETHERSCAN_V2 = "https://api.etherscan.io/v2/api";
const PAGE_SIZE = 1000;
const MAX_PAGES = 10; // safety bound (10k events) — plenty for a normal wallet

export interface DiscoveredPair {
  kind: "erc20" | "nft";
  token: string; // contract that emitted the event
  spender: string; // spender (ERC-20) or operator (NFT)
}

interface EtherscanLog {
  address: string;
  topics: string[];
  data: string;
}

function ownerTopic(owner: string): string {
  return "0x" + "0".repeat(24) + owner.toLowerCase().replace(/^0x/, "");
}
function topicToAddress(topic: string): string {
  return "0x" + topic.slice(-40).toLowerCase();
}

/** Page through Etherscan v2 getLogs for one event topic filtered by owner. */
async function getLogsByTopic(
  topic0: string,
  owner: string,
  apiKey: string,
  chainId = 1,
): Promise<EtherscanLog[]> {
  const out: EtherscanLog[] = [];
  for (let page = 1; page <= MAX_PAGES; page++) {
    const qs = new URLSearchParams({
      chainid: String(chainId),
      module: "logs",
      action: "getLogs",
      fromBlock: "0",
      toBlock: "latest",
      topic0,
      topic0_1_opr: "and",
      topic1: ownerTopic(owner),
      page: String(page),
      offset: String(PAGE_SIZE),
      apikey: apiKey,
    });
    const res = await fetch(`${ETHERSCAN_V2}?${qs}`, { signal: AbortSignal.timeout(15000) });
    const json = (await res.json()) as { status: string; message: string; result: unknown };
    // status "0" with "No records found" is a normal empty result, not an error.
    if (json.status !== "1") {
      if (typeof json.message === "string" && /no records/i.test(json.message)) break;
      throw new Error(`Etherscan: ${json.message} ${typeof json.result === "string" ? json.result : ""}`.trim());
    }
    const rows = (json.result as EtherscanLog[]) ?? [];
    out.push(...rows);
    if (rows.length < PAGE_SIZE) break; // last page
  }
  return out;
}

/** Discover all current-ish approval candidates for an owner. Throws on a real
 *  API error (bad key, rate limit) so the caller can surface it honestly. */
export async function discoverViaEtherscan(owner: string, apiKey: string): Promise<DiscoveredPair[]> {
  const [erc20Logs, nftLogs] = await Promise.all([
    getLogsByTopic(TOPIC_APPROVAL, owner, apiKey),
    getLogsByTopic(TOPIC_APPROVAL_FOR_ALL, owner, apiKey),
  ]);

  const pairs = new Map<string, DiscoveredPair>();

  for (const l of erc20Logs) {
    // ERC-20 Approval has 3 topics + data. ERC-721 single-token Approval shares the
    // same topic0 but has 4 topics (tokenId indexed) and empty data — skip those
    // here (single-NFT approvals are lower-risk than ApprovalForAll; Phase 1.1).
    if (!l.topics || l.topics.length !== 3) continue;
    const token = l.address.toLowerCase();
    const spender = topicToAddress(l.topics[2]);
    pairs.set(`erc20:${token}:${spender}`, { kind: "erc20", token, spender });
  }
  for (const l of nftLogs) {
    if (!l.topics || l.topics.length < 3) continue;
    const token = l.address.toLowerCase();
    const operator = topicToAddress(l.topics[2]);
    pairs.set(`nft:${token}:${operator}`, { kind: "nft", token, spender: operator });
  }

  return [...pairs.values()];
}

export function isPermit2(spender: string): boolean {
  return spender.toLowerCase() === PERMIT2_ADDRESS;
}
