// Minimal JSON-RPC client over fetch — zero dependencies. Enough to read an
// account's code (for EIP-7702 detection). The full approval enumeration in a
// later phase will use viem; v1 keeps the live path tiny and dependency-free.

// Reliable full-history `eth_getLogs` (needed to enumerate approvals) requires a
// keyed endpoint — anonymous free RPCs cap the block range (PublicNode 50k) or
// demand a key (Ankr). If ALCHEMY_KEY or a custom RPC_URL is set we use it FIRST
// (Alchemy free tier allows wide ranges, bounded by a 10k-result cap); otherwise
// we fall back to public RPCs, which still serve eth_getCode (the 7702 check) fine
// but will make approval enumeration fall back to the demo fixture.
function buildRpcs(): string[] {
  const list: string[] = [];
  if (process.env.RPC_URL) list.push(process.env.RPC_URL);
  if (process.env.ALCHEMY_KEY) list.push(`https://eth-mainnet.g.alchemy.com/v2/${process.env.ALCHEMY_KEY}`);
  list.push(
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://rpc.ankr.com/eth",
  );
  return list;
}

const DEFAULT_RPCS = buildRpcs();

let rpcId = 1;

export async function rpcCall(
  method: string,
  params: unknown[],
  rpcs: string[] = DEFAULT_RPCS,
  timeoutMs = 8000,
): Promise<unknown> {
  let lastErr: unknown;
  for (const url of rpcs) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: rpcId++, method, params }),
        signal: ctrl.signal,
      });
      clearTimeout(t);
      if (!res.ok) {
        lastErr = new Error(`${url} → HTTP ${res.status}`);
        continue;
      }
      const json = (await res.json()) as { result?: unknown; error?: { message: string } };
      if (json.error) {
        lastErr = new Error(`${url} → ${json.error.message}`);
        continue;
      }
      return json.result;
    } catch (e) {
      clearTimeout(t);
      lastErr = e;
      continue;
    }
  }
  throw new Error(`all RPCs failed: ${String(lastErr)}`);
}

/** eth_getCode for an address at latest block. Returns hex string ("0x..."). */
export async function getCode(address: string, rpcs?: string[]): Promise<string> {
  const r = await rpcCall("eth_getCode", [address, "latest"], rpcs);
  return typeof r === "string" ? r : "0x";
}
