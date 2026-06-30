#!/usr/bin/env node
// Sentinel CLI — the v1 entry point.
//
//   node src/cli/scan.ts                 # offline demo on the sample wallet
//   node src/cli/scan.ts --live <addr>   # real on-chain EIP-7702 delegation check
//
// Offline mode runs the full risk engine over a realistic fixture (always works,
// no network). Live mode does a real eth_getCode read to detect a 7702 delegation.

import { scoreWallet } from "../core/risk.ts";
import { renderReport } from "../core/report.ts";
import { SAMPLE_ADDRESS, SAMPLE_APPROVALS } from "../fixtures/sampleWallet.ts";
import { liveScan } from "../chain/scan.ts";

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const liveIdx = args.indexOf("--live");

  if (liveIdx !== -1) {
    const address = args[liveIdx + 1];
    if (!address || !/^0x[0-9a-fA-F]{40}$/.test(address)) {
      console.error("usage: node src/cli/scan.ts --live <0x-address>");
      process.exit(1);
    }
    console.error(`\n  …reading on-chain code for ${address}`);
    try {
      const { delegation, rawCode } = await liveScan(address);
      // v1 live mode reports delegation status (the wedge). Approvals come next phase.
      const report = scoreWallet(address, [], delegation);
      console.log(renderReport(report));
      if (!delegation.delegated) {
        console.log(`  Result: no EIP-7702 delegation on this account (code: ${rawCode.slice(0, 12)}…).\n`);
      }
    } catch (e) {
      console.error(`  live scan failed (network?): ${String(e)}`);
      console.error(`  tip: run without --live for the offline demo.\n`);
      process.exit(2);
    }
    return;
  }

  // Offline demo — full engine over the sample wallet.
  const report = scoreWallet(SAMPLE_ADDRESS, SAMPLE_APPROVALS);
  console.log(renderReport(report));
  console.log(`  ${"\x1b[2m"}(demo data · run with --live <address> for a real delegation check)\x1b[0m\n`);
}

main();
