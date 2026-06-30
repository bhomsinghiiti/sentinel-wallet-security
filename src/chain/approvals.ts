// Live approval enumeration.
//
// Two-phase, read-only, and the data source is swappable:
//   1. DISCOVER candidate (token, spender) pairs from the event log.
//        • ETHERSCAN_KEY set  → Etherscan v2 (reliable full-history; works for anyone).
//        • else               → raw eth_getLogs best-effort (free RPCs cap this; often null).
//   2. VERIFY current state with cheap eth_call (allowance / isApprovedForAll) over
//      whatever RPC rpc.ts resolves (public RPCs serve eth_call fine — no key needed).
// Returns null only when discovery itself is unavailable, so the UI can be honest.

import { rpcCall } from "./rpc.ts";
import { discoverViaEtherscan, isPermit2, type DiscoveredPair } from "./etherscan.ts";
import type { Approval } from "../core/types.ts";

const TOPIC_APPROVAL = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925";
const TOPIC_APPROVAL_FOR_ALL = "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31";
const SEL_ALLOWANCE = "0xdd62ed3e"; // allowance(address,address)
const SEL_IS_APPROVED_FOR_ALL = "0xe985e9c5"; // isApprovedForAll(address,address)
const SEL_SYMBOL = "0x95d89b41"; // symbol()

function pad32(addr: string): string {
  return addr.toLowerCase().replace(/^0x/, "").padStart(64, "0");
}
function topicToAddress(topic: string): string {
  return "0x" + topic.slice(-40);
}

/** Enumerate a wallet's current ERC-20 + NFT approvals. null = discovery unavailable. */
export async function liveApprovals(owner: string): Promise<Approval[] | null> {
  let pairs: DiscoveredPair[];
  const key = process.env.ETHERSCAN_KEY;
  if (key) {
    try {
      pairs = await discoverViaEtherscan(owner, key);
    } catch {
      return null; // bad key / rate limit — surface honestly
    }
  } else {
    const raw = await discoverViaRawLogs(owner);
    if (raw === null) return null; // free RPC capped the query
    pairs = raw;
  }
  return verifyPairs(owner, pairs);
}

/** Phase-2 verification: read the CURRENT allowance for each candidate; drop dead ones.
 *  NOTE: in v0.1 every live spender is marked verified:false / flagged:false /
 *  knownDrainer:false — there is no reputation source wired yet (that's Phase 1), so the
 *  `flagged`/`knownDrainer` risk rules only fire on fixture data, not live scans. */
async function verifyPairs(owner: string, pairs: DiscoveredPair[]): Promise<Approval[]> {
  const out: Approval[] = [];

  for (const { kind, token, spender } of pairs.slice(0, 60)) {
    try {
      if (kind === "erc20") {
        const data = SEL_ALLOWANCE + pad32(owner) + pad32(spender);
        const res = (await rpcCall("eth_call", [{ to: token, data }, "latest"])) as string;
        const val = toBigInt(res);
        if (val === null || val === 0n) continue; // allowance 0 / unreadable → revoked/spent
        // Treat anything ≥ 2^255 as effectively unlimited (covers 2^256-1 and near-max sentinels).
        const unlimited = val >= 1n << 255n;
        out.push({
          kind: "erc20",
          asset: await safeSymbol(token),
          spender: { address: spender, verified: false, flagged: false, knownDrainer: false, permit2: isPermit2(spender) },
          unlimited,
          allowance: unlimited ? "Unlimited" : `${shortHex(res)} (raw)`,
          lastUsedDaysAgo: null,
          exposureUsd: 0,
        });
      } else {
        const data = SEL_IS_APPROVED_FOR_ALL + pad32(owner) + pad32(spender);
        const res = (await rpcCall("eth_call", [{ to: token, data }, "latest"])) as string;
        // isApprovedForAll returns a 32-byte ABI bool; decode the whole word, not the last nibble.
        const approved = toBigInt(res);
        if (approved === null || approved === 0n) continue; // not approved-for-all anymore
        out.push({
          kind: "nft",
          asset: await safeSymbol(token),
          spender: { address: spender, verified: false, flagged: false, knownDrainer: false },
          unlimited: true,
          allowance: "ALL NFTs",
          lastUsedDaysAgo: null,
          exposureUsd: 0,
        });
      }
    } catch {
      /* skip this pair */
    }
  }
  return out;
}

/** Fallback discovery via raw eth_getLogs (free RPCs usually reject full history → null). */
async function discoverViaRawLogs(owner: string): Promise<DiscoveredPair[] | null> {
  const ownerTopic = "0x" + pad32(owner);
  let erc20Logs: { address: string; topics: string[] }[];
  let nftLogs: { address: string; topics: string[] }[];
  try {
    [erc20Logs, nftLogs] = await Promise.all([
      rpcCall("eth_getLogs", [{ fromBlock: "0x0", toBlock: "latest", topics: [TOPIC_APPROVAL, ownerTopic] }]) as Promise<{ address: string; topics: string[] }[]>,
      rpcCall("eth_getLogs", [{ fromBlock: "0x0", toBlock: "latest", topics: [TOPIC_APPROVAL_FOR_ALL, ownerTopic] }]) as Promise<{ address: string; topics: string[] }[]>,
    ]);
  } catch {
    return null;
  }
  const pairs = new Map<string, DiscoveredPair>();
  for (const l of erc20Logs ?? []) {
    if (l.topics?.length !== 3) continue;
    const token = l.address.toLowerCase();
    const spender = topicToAddress(l.topics[2]);
    pairs.set(`erc20:${token}:${spender}`, { kind: "erc20", token, spender });
  }
  for (const l of nftLogs ?? []) {
    if (!l.topics || l.topics.length < 3) continue; // guard undefined before indexing
    const token = l.address.toLowerCase();
    const spender = topicToAddress(l.topics[2]);
    pairs.set(`nft:${token}:${spender}`, { kind: "nft", token, spender });
  }
  return [...pairs.values()];
}

async function safeSymbol(token: string): Promise<string> {
  try {
    const res = (await rpcCall("eth_call", [{ to: token, data: SEL_SYMBOL }, "latest"])) as string;
    return decodeString(res) || token.slice(0, 8);
  } catch {
    return token.slice(0, 8);
  }
}
function shortHex(h: string): string {
  return h.length > 14 ? h.slice(0, 10) + "…" : h;
}
/** Parse a 32-byte ABI word into a bigint; null if empty/unparseable ("0x"). */
function toBigInt(hex: string | null | undefined): bigint | null {
  if (!hex || hex === "0x") return null;
  try {
    return BigInt(hex.trim());
  } catch {
    return null;
  }
}
function decodeString(hex: string): string {
  if (!hex || hex === "0x") return "";
  const body = hex.replace(/^0x/, "");
  if (body.length < 128) return hexToUtf8(body.replace(/00+$/, ""));
  const len = parseInt(body.slice(64, 128), 16);
  return hexToUtf8(body.slice(128, 128 + len * 2));
}
function hexToUtf8(h: string): string {
  let s = "";
  for (let i = 0; i < h.length; i += 2) {
    const code = parseInt(h.slice(i, i + 2), 16);
    if (code > 0) s += String.fromCharCode(code);
  }
  return s.trim();
}
