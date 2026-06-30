// Terminal renderer for a WalletReport. Pure string-building (no I/O), so the CLI
// stays a thin shell and the formatting is testable if we ever want to.

import type { WalletReport, RiskLevel } from "./types.ts";

const C = {
  reset: "\x1b[0m",
  dim: "\x1b[2m",
  bold: "\x1b[1m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  green: "\x1b[32m",
  cyan: "\x1b[36m",
  gray: "\x1b[90m",
};

const LEVEL_TAG: Record<RiskLevel, string> = {
  critical: `${C.red}${C.bold}CRITICAL${C.reset}`,
  high: `${C.yellow}${C.bold}HIGH    ${C.reset}`,
  medium: `${C.yellow}MEDIUM  ${C.reset}`,
  low: `${C.green}LOW     ${C.reset}`,
  safe: `${C.green}SAFE    ${C.reset}`,
};

function usd(n: number): string {
  return "$" + Math.round(n).toLocaleString("en-US");
}

export function renderReport(r: WalletReport, color = true): string {
  const c = color ? C : new Proxy({}, { get: () => "" }) as typeof C;
  const out: string[] = [];

  out.push("");
  out.push(`${c.cyan}${c.bold}  🛡  SENTINEL — wallet risk scan${c.reset}`);
  out.push(`  ${c.gray}${r.address}${c.reset}`);
  out.push("");

  const bandColor =
    r.band === "CRITICAL" ? c.red : r.band === "HIGH" ? c.yellow : r.band === "ELEVATED" ? c.yellow : c.green;
  out.push(
    `  Risk score: ${bandColor}${c.bold}${r.score}/100 · ${r.band}${c.reset}` +
      `   ${c.gray}|${c.reset}   At risk: ${c.bold}${usd(r.atRiskUsd)}${c.reset}` +
      `   ${c.gray}|${c.reset}   ${c.red}${r.counts.critical} critical${c.reset}, ${c.yellow}${r.counts.high} high${c.reset}, ${r.counts.medium} med, ${r.counts.low} low`,
  );

  // EIP-7702 delegation banner (the wedge) — shown first when present.
  if (r.delegation?.delegated) {
    out.push("");
    if (r.delegation.malicious) {
      out.push(`  ${c.red}${c.bold}⚠ EIP-7702 DELEGATION — MALICIOUS${c.reset}`);
      out.push(
        `    Your account is delegated to ${c.red}${r.delegation.delegateLabel ?? r.delegation.delegate}${c.reset}.`,
      );
      out.push(`    ${c.dim}Reset the delegation to 0x000…0000 (you sign it; Sentinel never can).${c.reset}`);
    } else {
      out.push(`  ${c.yellow}⚠ EIP-7702 DELEGATION present${c.reset} → ${r.delegation.delegate}`);
      out.push(`    ${c.dim}Confirm you set this intentionally.${c.reset}`);
    }
  }

  out.push("");
  out.push(`  ${c.gray}${"─".repeat(64)}${c.reset}`);
  for (const f of r.findings) {
    out.push(
      `  ${LEVEL_TAG[f.level]}  ${c.bold}${f.approval.asset}${c.reset} ${c.gray}→${c.reset} ${f.approval.spender.label ?? f.approval.spender.address}` +
        `  ${c.gray}[${f.approval.allowance}]${c.reset}`,
    );
    out.push(`            ${c.dim}${f.reason}${c.reset}`);
  }
  out.push(`  ${c.gray}${"─".repeat(64)}${c.reset}`);
  out.push(
    `  ${c.dim}Sentinel is read-only & non-custodial. Every revoke is a tx you sign yourself.${c.reset}`,
  );
  out.push("");
  return out.join("\n");
}
