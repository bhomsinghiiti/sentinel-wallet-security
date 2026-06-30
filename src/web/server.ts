// Sentinel local web app — a zero-dependency Node HTTP server you run on your own
// machine. Serves a UI at http://localhost:3000 and a /api/scan endpoint that runs
// the real engine: a live EIP-7702 delegation check + best-effort live approval
// enumeration (falls back to the demo fixture if a free RPC caps the query).
//
//   npm run web        →  open http://localhost:3000

import { createServer } from "node:http";
import { scoreWallet } from "../core/risk.ts";
import { buildRevoke } from "../core/revoke.ts";
import { liveScan } from "../chain/scan.ts";
import { liveApprovals } from "../chain/approvals.ts";
import { SAMPLE_APPROVALS } from "../fixtures/sampleWallet.ts";
import type { Approval } from "../core/types.ts";

const PORT = Number(process.env.PORT ?? 3000);

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://localhost:${PORT}`);

  if (url.pathname === "/") {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(PAGE);
    return;
  }

  if (url.pathname === "/api/scan") {
    const address = url.searchParams.get("address") ?? "";
    if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "Enter a valid 0x address (or connect a wallet)." }));
      return;
    }
    try {
      const { delegation } = await liveScan(address); // always a real on-chain read
      let approvals: Approval[];
      let source: "live" | "clean" | "unavailable" | "demo";

      if (url.searchParams.get("demo") === "1") {
        // Explicit demo of what a messy wallet looks like.
        approvals = SAMPLE_APPROVALS;
        source = "demo";
      } else {
        const live = await liveApprovals(address); // Approval[] | null
        if (live === null) {
          // RPC capped/failed — be honest, show NO approvals (never fake ones).
          approvals = [];
          source = "unavailable";
        } else {
          approvals = live;
          source = live.length === 0 ? "clean" : "live";
        }
      }
      const report = scoreWallet(address, approvals, delegation);
      // Attach the (tested, pure) revoke calldata per finding so the browser only signs.
      const findings = report.findings.map((f) => ({ ...f, revoke: buildRevoke(f.approval) }));
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ report: { ...report, findings }, source }));
    } catch (e) {
      // Log the detail server-side; never return it — RPC errors can contain a
      // keyed endpoint URL. The client gets a generic message.
      console.error("scan failed:", e);
      res.writeHead(502, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "Scan failed (network/RPC). Please try again." }));
    }
    return;
  }

  res.writeHead(404);
  res.end("not found");
});

// Bind to loopback only — this is a local tool, not a LAN/public service. Binding
// all interfaces would let anyone on the network burn the configured API quota.
server.listen(PORT, "127.0.0.1", () => {
  console.log(`\n  🛡  Sentinel running →  http://localhost:${PORT}\n`);
});

const PAGE = /* html */ `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentinel — wallet security</title>
<style>
:root{--bg:#0C0F15;--bg2:#141A26;--bg3:#1C2434;--line:#28324A;--text:#E9EEF6;--dim:#94A1B4;--acc:#2BA6E8;--crit:#FF5C5C;--high:#FF9D42;--med:#E6C13A;--low:#46D08A;--mono:"SF Mono",ui-monospace,Menlo,monospace}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:760px;margin:0 auto;padding:28px 20px 80px}
.logo{display:flex;align-items:center;gap:9px;font-weight:800;font-size:20px;letter-spacing:-.02em;margin-bottom:6px}
.logo .m{width:30px;height:30px;border-radius:8px;background:linear-gradient(145deg,#2BA6E8,#1c6fb0);display:flex;align-items:center;justify-content:center}
.sub{color:var(--dim);margin:0 0 22px}
.bar{display:flex;gap:9px;flex-wrap:wrap}
input{flex:1;min-width:240px;background:var(--bg2);border:1px solid var(--line);border-radius:10px;color:var(--text);font-family:var(--mono);font-size:14px;padding:12px 14px;outline:none}
input:focus{border-color:var(--acc)}
button{font-weight:700;font-size:14px;border-radius:10px;padding:12px 18px;border:1px solid var(--line);background:var(--bg2);color:var(--text);cursor:pointer}
button.p{background:var(--acc);border-color:var(--acc);color:#04121d}
button:hover{filter:brightness(1.1)}
.note{margin:12px 0 0;font-size:12.5px;color:var(--dim)}
#out{margin-top:24px}
.score{display:flex;gap:18px;align-items:center;background:var(--bg2);border:1px solid var(--line);border-radius:12px;padding:18px;flex-wrap:wrap}
.score .n{font-weight:800;font-size:30px;font-variant-numeric:tabular-nums}
.score .meta{color:var(--dim);font-size:13px}
.badge{font-family:var(--mono);font-size:11px;font-weight:700;padding:3px 9px;border-radius:20px}
.b-CRITICAL{color:var(--crit);background:#2e1416}.b-HIGH{color:var(--high);background:#2c1d0e}.b-ELEVATED{color:var(--med);background:#272109}.b-LOW{color:var(--low);background:#0e2a1d}
.deleg{margin-top:14px;border:1px solid var(--crit);background:#22090b;border-radius:12px;padding:16px}
.deleg.ok{border-color:#2a6b46;background:#0e2a1d}
.deleg h3{margin:0 0 6px;font-size:15px}.deleg p{margin:0;font-size:13px;color:var(--dim)}
.row{display:flex;gap:12px;align-items:flex-start;padding:14px 0;border-bottom:1px solid var(--line)}
.chip{font-family:var(--mono);font-size:10px;font-weight:700;padding:4px 8px;border-radius:6px;text-transform:uppercase;white-space:nowrap;flex:none;width:64px;text-align:center}
.c-critical{color:var(--crit);background:#2e1416}.c-high{color:var(--high);background:#2c1d0e}.c-medium{color:var(--med);background:#272109}.c-low{color:var(--low);background:#0e2a1d}
.row .a{font-weight:700}.row .s{color:var(--dim);font-size:12px;font-family:var(--mono)}.row .r{color:var(--dim);font-size:13px;margin-top:3px}
.row .mid{flex:1;min-width:0}.row .ex{color:var(--high);font-weight:700;font-size:12px;font-family:var(--mono)}
.rev{flex:none;align-self:center;font-weight:700;font-size:12.5px;border:1px solid var(--line2);background:var(--bg3);color:var(--text);border-radius:8px;padding:7px 13px;cursor:pointer}
.rev:hover{border-color:var(--crit);color:var(--crit)}.rev:disabled{cursor:default;opacity:.8}
.rev.done{border-color:var(--low);color:var(--low);background:var(--low)10}
.src{font-size:12px;color:var(--dim);margin:14px 0;padding:9px 12px;border:1px dashed var(--line);border-radius:8px}
.err{color:var(--crit)}.spin{color:var(--acc)}
.foot{margin-top:26px;font-size:12px;color:#647085;line-height:1.5}
</style></head><body><div class="wrap">
<div class="logo"><span class="m">🛡</span> Sentinel</div>
<p class="sub">See everything that can drain your wallet — approvals &amp; EIP-7702 delegations. Read-only, non-custodial.</p>
<div class="bar">
  <input id="addr" placeholder="0x address…" spellcheck="false">
  <button class="p" id="scan">Scan</button>
  <button id="connect">Connect wallet</button>
</div>
<p class="note">We never request spending permission — connecting only reads your address. Or paste any address to scan it.</p>
<div id="out"></div>
<p class="foot">Sentinel reads public on-chain data (your past Approval events + current allowances). Scanning is free. Revoking — coming next — is a transaction <b>you</b> sign and pay network gas for; Sentinel holds no keys and takes no fee.</p>
</div>
<script>
const out=document.getElementById('out'),addr=document.getElementById('addr');
const ESC=s=>String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
document.getElementById('connect').onclick=async()=>{
  if(!window.ethereum){out.innerHTML='<p class="err">No wallet found. Install MetaMask, or paste an address.</p>';return;}
  try{const a=await window.ethereum.request({method:'eth_requestAccounts'});addr.value=a[0];scan();}catch(e){out.innerHTML='<p class="err">'+ESC(e.message||e)+'</p>';}
};
document.getElementById('scan').onclick=scan;
addr.addEventListener('keydown',e=>{if(e.key==='Enter')scan();});
// One-click revoke — user signs in their own wallet; we only hand over the calldata.
out.addEventListener('click',async e=>{
  const b=e.target.closest('.rev'); if(!b) return;
  if(!window.ethereum){alert('No wallet found — install MetaMask to revoke.');return;}
  const old=b.textContent;
  try{
    const accs=await window.ethereum.request({method:'eth_requestAccounts'});
    b.disabled=true;b.textContent='Confirm in wallet…';
    await window.ethereum.request({method:'eth_sendTransaction',params:[{from:accs[0],to:b.dataset.to,data:b.dataset.data}]});
    b.textContent='Revoked ✓';b.classList.add('done');
  }catch(err){b.disabled=false;b.textContent=old;alert('Revoke cancelled/failed: '+ESC(err.message||String(err)));}
});
async function scan(){
  const a=addr.value.trim();
  if(!/^0x[0-9a-fA-F]{40}$/.test(a)){out.innerHTML='<p class="err">Enter a valid 0x address.</p>';return;}
  out.innerHTML='<p class="spin">Reading on-chain data…</p>';
  try{
    const res=await fetch('/api/scan?address='+a);const j=await res.json();
    if(j.error){out.innerHTML='<p class="err">'+ESC(j.error)+'</p>';return;}
    render(j.report,j.source);
  }catch(e){out.innerHTML='<p class="err">'+ESC(e.message||e)+'</p>';}
}
function render(r,source){
  let h='<div class="score"><div class="n">'+r.score+'/100</div>'+
    '<span class="badge b-'+r.band+'">'+r.band+'</span>'+
    '<div class="meta">At risk: <b>$'+Math.round(r.atRiskUsd).toLocaleString()+'</b> · '+
    r.counts.critical+' critical, '+r.counts.high+' high, '+r.counts.medium+' med, '+r.counts.low+' low</div></div>';
  if(r.delegation&&r.delegation.delegated){
    const bad=r.delegation.malicious;
    h+='<div class="deleg'+(bad?'':' ok')+'"><h3>'+(bad?'⚠ EIP-7702 delegation — MALICIOUS':'⚠ EIP-7702 delegation present')+'</h3>'+
      '<p>Delegate: <span style="font-family:var(--mono)">'+ESC(r.delegation.delegate||'')+'</span>'+(r.delegation.delegateLabel?' ('+ESC(r.delegation.delegateLabel)+')':'')+
      '. '+(bad?'Reset to the zero address — you sign it.':'Confirm you set this intentionally.')+'</p></div>';
  }
  if(source==='unavailable')h+='<div class="src">⚠ Your <b>real approvals could not be read</b>: discovery needs a free indexed-data key (anonymous public RPCs cap full-history <code>eth_getLogs</code> — verified). The EIP-7702 check above <b>is</b> live. To read your real approvals, run with a free Etherscan key: <code>ETHERSCAN_KEY=xxx PORT=7702 npm run web</code> (see docs/APPROVAL-DATA.md). These are NOT sample approvals — none are shown because we won\\'t guess.</div>';
  if(source==='clean')h+='<div class="src">✓ Live read succeeded and found <b>no open approvals</b> for this wallet.</div>';
  if(source==='demo')h+='<div class="src">This is <b>sample data</b> showing what a messy wallet looks like — not a real wallet. (Add <code>?demo=1</code> triggered this view.)</div>';
  if(source==='live')h+='<div class="src">✓ <b>Live</b> approvals read from chain for this wallet.</div>';
  for(const f of r.findings.filter(f=>f.approval.kind!=='delegation')){
    const ex=f.approval.exposureUsd>0?' · <span class="ex">$'+Math.round(f.approval.exposureUsd).toLocaleString()+' at risk</span>':'';
    const btn=f.revoke?'<button class="rev" data-to="'+ESC(f.revoke.to)+'" data-data="'+ESC(f.revoke.data)+'">Revoke</button>':'';
    h+='<div class="row"><span class="chip c-'+f.level+'">'+f.level+'</span>'+
      '<div class="mid"><span class="a">'+ESC(f.approval.asset)+'</span> <span class="s">→ '+ESC(f.approval.spender.label||f.approval.spender.address)+' ['+ESC(f.approval.allowance)+']</span>'+ex+
      '<div class="r">'+ESC(f.reason)+'</div></div>'+btn+'</div>';
  }
  if(!r.findings.length && (source==='clean'||source==='live'||source==='demo'))h+='<p class="note">No open approvals or delegations found — this wallet looks clean. ✓</p>';
  if(!r.findings.length && source==='unavailable')h+='<p class="note">No EIP-7702 delegation found (live ✓). Approvals not read — add a data key above to see them.</p>';
  out.innerHTML=h;
}
</script></body></html>`;
