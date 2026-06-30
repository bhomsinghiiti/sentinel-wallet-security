// Reputation layer — "rent the judgment" via GoPlus Security's free, keyless API.
// Two lookups: address_security (is this spender a known drainer/phisher/sanctioned?)
// and token_security (is this token trusted / a honeypot?). Cached per address.
// Dependency-free fetch; on any failure we return "unknown" (never a false clean).

const GOPLUS = "https://api.gopluslabs.io/api/v1";

export interface AddressRep {
  /** A known-bad address (phishing/stealing/sanctioned/blacklisted). */
  malicious: boolean;
  /** Human reasons, e.g. ["phishing", "sanctioned"]. */
  reasons: string[];
  /** True only if the lookup actually succeeded (so callers can distinguish unknown). */
  resolved: boolean;
}

export interface TokenRep {
  trusted: boolean; // GoPlus trust_list === "1"
  honeypot: boolean; // is_honeypot === "1"
  resolved: boolean;
}

const addrCache = new Map<string, AddressRep>();
const tokenCache = new Map<string, TokenRep>();

// The address_security flags we treat as "known bad" (value "1").
const BAD_FLAGS: Record<string, string> = {
  phishing_activities: "phishing",
  stealing_attack: "wallet drainer",
  cybercrime: "cybercrime",
  money_laundering: "money laundering",
  financial_crime: "financial crime",
  darkweb_transactions: "darkweb activity",
  blacklist_doubt: "blacklisted",
  sanctioned: "sanctioned",
  fake_kyc: "fake KYC",
  honeypot_related_address: "honeypot-related",
};

async function gget(url: string): Promise<Record<string, unknown> | null> {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(10000) });
    if (!res.ok) return null;
    const json = (await res.json()) as { code?: number; result?: Record<string, unknown> };
    if (json.code !== 1 || !json.result) return null;
    return json.result;
  } catch {
    return null;
  }
}

/** Is this spender a known drainer / scam / sanctioned address? */
export async function addressReputation(addr: string, chainId = 1): Promise<AddressRep> {
  const key = `${chainId}:${addr.toLowerCase()}`;
  const cached = addrCache.get(key);
  if (cached) return cached;

  const result = await gget(`${GOPLUS}/address_security/${addr.toLowerCase()}?chain_id=${chainId}`);
  let rep: AddressRep;
  if (!result) {
    rep = { malicious: false, reasons: [], resolved: false };
  } else {
    const reasons: string[] = [];
    for (const [flag, label] of Object.entries(BAD_FLAGS)) {
      if (result[flag] === "1") reasons.push(label);
    }
    rep = { malicious: reasons.length > 0, reasons, resolved: true };
  }
  addrCache.set(key, rep);
  return rep;
}

/** Is this token trusted (blue-chip) or a honeypot? */
export async function tokenReputation(token: string, chainId = 1): Promise<TokenRep> {
  const key = `${chainId}:${token.toLowerCase()}`;
  const cached = tokenCache.get(key);
  if (cached) return cached;

  const result = await gget(`${GOPLUS}/token_security/${chainId}?contract_addresses=${token.toLowerCase()}`);
  let rep: TokenRep;
  if (!result) {
    rep = { trusted: false, honeypot: false, resolved: false };
  } else {
    const t = (result[token.toLowerCase()] ?? {}) as Record<string, unknown>;
    rep = { trusted: t.trust_list === "1", honeypot: t.is_honeypot === "1", resolved: true };
  }
  tokenCache.set(key, rep);
  return rep;
}
