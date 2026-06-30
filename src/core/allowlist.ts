// Curated allowlist of major mainnet contracts that wallets commonly approve.
// This is the dependency-free "stop crying wolf" layer: a spender on this list is a
// known, legitimate protocol, so an unlimited approval to it is routine (MEDIUM),
// not a CRITICAL "unverified contract" alarm. Addresses are lowercased.
//
// Seeded from the contracts the audit saw flagged as false-CRITICAL + the common
// routers/marketplaces. Fuller coverage (ethereum-lists/contracts, revoke.cash whois)
// is a follow-up — it needs EIP-55 checksumming; this static set covers the bulk.

export interface KnownContract {
  name: string;
  label: string;
}

export const ALLOWLIST: Record<string, KnownContract> = {
  // Uniswap
  "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": { name: "Uniswap", label: "Universal Router" },
  "0x66a9893cc07d91d95644aedd05d03f95e1dba8af": { name: "Uniswap", label: "Universal Router v2" },
  "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": { name: "Uniswap", label: "V2 Router 02" },
  "0xe592427a0aece92de3edee1f18e0157c05861564": { name: "Uniswap", label: "V3 SwapRouter" },
  "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad": { name: "Uniswap", label: "Universal Router (old)" },
  // Permit2
  "0x000000000022d473030f116ddee9f6b43ac78ba3": { name: "Uniswap", label: "Permit2" },
  // 1inch
  "0x111111125421ca6dc452d289314280a0f8842a65": { name: "1inch", label: "Aggregation Router v6" },
  "0x1111111254eeb25477b68fb85ed929f73a960582": { name: "1inch", label: "Aggregation Router v5" },
  // 0x
  "0xdef1c0ded9bec7f1a1670819833240f027b25eff": { name: "0x", label: "Exchange Proxy" },
  // CowSwap
  "0xc92e8bdf79f0507f65a392b0ab4667716bfe0110": { name: "CoW Protocol", label: "GPv2 Vault Relayer" },
  // Paraswap
  "0x216b4b4ba9f3e719726886d34a177484278bfcae": { name: "ParaSwap", label: "Token Transfer Proxy" },
  // OpenSea / Seaport
  "0x00000000006c3852cbef3e08e8df289169ede581": { name: "OpenSea", label: "Seaport 1.1" },
  "0x00000000000000adc04c56bf30ac9d3c0aaf14dc": { name: "OpenSea", label: "Seaport 1.5" },
  "0x1e0049783f008a0085193e00003d00cd54003c71": { name: "OpenSea", label: "Conduit" },
  // Aave v3
  "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2": { name: "Aave", label: "v3 Pool" },
  // Lido
  "0x889edc2edab5f40e902b864ad4d7ade8e412f9b1": { name: "Lido", label: "Withdrawal Queue" },
};

/** Look up a spender in the curated allowlist (case-insensitive). */
export function lookupKnown(address: string): KnownContract | undefined {
  return ALLOWLIST[address.toLowerCase()];
}
