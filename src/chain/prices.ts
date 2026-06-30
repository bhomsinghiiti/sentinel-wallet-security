// USD prices via DefiLlama's free, keyless Coins API. Batched (one call for all
// tokens) and returns decimals + a confidence score in the same payload, so we can
// reject fake spam-token liquidity (confidence < 0.9) — the keyless equivalent of
// revoke.cash's $50k-reserve guard.

export interface TokenPrice {
  price: number;
  decimals: number;
  confidence: number;
  symbol?: string;
}

const cache = new Map<string, TokenPrice | null>();

/** Fetch USD prices for many mainnet tokens in one call. Map key = lowercased address. */
export async function getPrices(tokens: string[], chain = "ethereum"): Promise<Map<string, TokenPrice>> {
  const out = new Map<string, TokenPrice>();
  const need: string[] = [];
  for (const t of tokens) {
    const k = t.toLowerCase();
    if (cache.has(k)) {
      const v = cache.get(k);
      if (v) out.set(k, v);
    } else {
      need.push(k);
    }
  }
  if (need.length === 0) return out;

  const ids = need.map((t) => `${chain}:${t}`).join(",");
  try {
    const res = await fetch(`https://coins.llama.fi/prices/current/${ids}`, {
      signal: AbortSignal.timeout(10000),
    });
    if (res.ok) {
      const json = (await res.json()) as { coins?: Record<string, TokenPrice> };
      const coins = json.coins ?? {};
      for (const t of need) {
        const c = coins[`${chain}:${t}`];
        if (c && typeof c.price === "number") {
          const p: TokenPrice = { price: c.price, decimals: c.decimals, confidence: c.confidence ?? 0, symbol: c.symbol };
          cache.set(t, p);
          // Only trust prices with real liquidity behind them.
          if (p.confidence >= 0.9) out.set(t, p);
        } else {
          cache.set(t, null);
        }
      }
    }
  } catch {
    /* leave prices unknown */
  }
  return out;
}
