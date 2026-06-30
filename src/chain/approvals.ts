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
import { lookupKnown } from "../core/allowlist.ts";
import { addressReputation, tokenReputation } from "./reputation.ts";
import { getPrices } from "./prices.ts";
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

/** Phase-2: read CURRENT allowance for each candidate; drop dead ones; then ENRICH
 *  each with the allowlist (trusted contracts), reputation (GoPlus drainer/honeypot),
 *  and USD value-at-risk (balanceOf × DefiLlama price). This is the judgment layer. */
async function verifyPairs(owner: string, pairs: DiscoveredPair[]): Promise<Approval[]> {
  const base: { a: Approval; rawAllowance: bigint }[] = [];

  // --- current-state verification (keep only live approvals) ---
  for (const { kind, token, spender } of pairs.slice(0, 60)) {
    try {
      if (kind === "erc20") {
        const data = SEL_ALLOWANCE + pad32(owner) + pad32(spender);
        const res = (await rpcCall("eth_call", [{ to: token, data }, "latest"])) as string;
        const val = toBigInt(res);
        if (val === null || val === 0n) continue;
        const unlimited = val >= 1n << 255n;
        base.push({
          rawAllowance: val,
          a: {
            kind: "erc20", asset: await safeSymbol(token), token,
            spender: { address: spender, verified: false, flagged: false, knownDrainer: false, permit2: isPermit2(spender) },
            unlimited, allowance: unlimited ? "Unlimited" : `${shortHex(res)} (raw)`,
            lastUsedDaysAgo: null, exposureUsd: 0,
          },
        });
      } else {
        const data = SEL_IS_APPROVED_FOR_ALL + pad32(owner) + pad32(spender);
        const res = (await rpcCall("eth_call", [{ to: token, data }, "latest"])) as string;
        const approved = toBigInt(res);
        if (approved === null || approved === 0n) continue;
        base.push({
          rawAllowance: 1n << 255n,
          a: {
            kind: "nft", asset: await safeSymbol(token), token,
            spender: { address: spender, verified: false, flagged: false, knownDrainer: false },
            unlimited: true, allowance: "ALL NFTs", lastUsedDaysAgo: null, exposureUsd: 0,
          },
        });
      }
    } catch {
      /* skip this pair */
    }
  }

  await enrich(owner, base);
  return base.map((b) => b.a);
}

/** Attach trusted-contract labels, drainer/honeypot reputation, and USD value-at-risk. */
async function enrich(owner: string, base: { a: Approval; rawAllowance: bigint }[]): Promise<void> {
  // 1. Allowlist (sync, offline): known protocols → verified + label.
  for (const { a } of base) {
    const known = lookupKnown(a.spender.address);
    if (known) {
      a.spender.verified = true;
      a.spender.label = a.spender.label ?? `${known.name}: ${known.label}`;
    }
  }

  const spenders = [...new Set(base.map((b) => b.a.spender.address))].slice(0, 40);
  const erc20Tokens = [...new Set(base.filter((b) => b.a.kind !== "nft").map((b) => b.a.token))].slice(0, 40);

  // 2. Reputation + prices + balances, in parallel.
  const [repBySpender, priceByToken, balByToken, hpByToken] = await Promise.all([
    mapAsync(spenders, (s) => addressReputation(s)),
    getPrices(erc20Tokens),
    mapAsync(erc20Tokens, (t) => balanceOf(owner, t)),
    mapAsync(erc20Tokens, (t) => tokenReputation(t)),
  ]);

  for (const { a, rawAllowance } of base) {
    const rep = repBySpender.get(a.spender.address);
    if (rep?.malicious) {
      a.spender.knownDrainer = true;
      a.spender.flagged = true;
      a.spender.label = `⚠ ${rep.reasons.join(", ")}`;
      a.spender.verified = false;
    }
    if (a.kind !== "nft") {
      if (hpByToken.get(a.token)?.honeypot) a.honeypot = true;
      const price = priceByToken.get(a.token.toLowerCase());
      const bal = balByToken.get(a.token);
      if (price && bal !== undefined && bal !== null) {
        const exposedRaw = rawAllowance < bal ? rawAllowance : bal; // min(allowance, balance)
        a.exposureUsd = (Number(exposedRaw) / 10 ** price.decimals) * price.price;
      }
    }
  }
}

/** Run an async fn over keys, returning a Map<key, result>. Bounded concurrency. */
async function mapAsync<T>(keys: string[], fn: (k: string) => Promise<T>): Promise<Map<string, T>> {
  const out = new Map<string, T>();
  const CONC = 8;
  for (let i = 0; i < keys.length; i += CONC) {
    const slice = keys.slice(i, i + CONC);
    const results = await Promise.all(slice.map(fn));
    slice.forEach((k, j) => out.set(k, results[j]));
  }
  return out;
}

const SEL_BALANCE_OF = "0x70a08231"; // balanceOf(address)
async function balanceOf(owner: string, token: string): Promise<bigint | null> {
  try {
    const res = (await rpcCall("eth_call", [{ to: token, data: SEL_BALANCE_OF + pad32(owner) }, "latest"])) as string;
    return toBigInt(res);
  } catch {
    return null;
  }
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
