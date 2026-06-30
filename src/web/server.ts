// Sentinel local web app — a zero-dependency Node HTTP server. Serves a polished UI
// at http://localhost:3000 (or $PORT) and a /api/scan endpoint that runs the real
// engine: live approval enumeration (Etherscan) + reputation (GoPlus) + USD value
// (DefiLlama) + EIP-7702 delegation detection, with one-click user-signed revoke.
//
//   npm run web        →  open http://localhost:7702 (PORT in .env)

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
      const { delegation } = await liveScan(address);
      let approvals: Approval[];
      let source: "live" | "clean" | "unavailable" | "demo";
      if (url.searchParams.get("demo") === "1") {
        approvals = SAMPLE_APPROVALS;
        source = "demo";
      } else {
        const live = await liveApprovals(address);
        if (live === null) {
          approvals = [];
          source = "unavailable";
        } else {
          approvals = live;
          source = live.length === 0 ? "clean" : "live";
        }
      }
      const report = scoreWallet(address, approvals, delegation);
      const findings = report.findings.map((f) => ({ ...f, revoke: buildRevoke(f.approval) }));
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ report: { ...report, findings }, source }));
    } catch (e) {
      console.error("scan failed:", e);
      res.writeHead(502, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "Scan failed (network/RPC). Please try again." }));
    }
    return;
  }

  res.writeHead(404);
  res.end("not found");
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`\n  🛡  Sentinel running →  http://localhost:${PORT}\n`);
});

const PAGE = /* html */ `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentinel — wallet security</title>
<style>
  :root{
    --bg:#0a0d13; --bg-grad:#0d1119; --surface:#11151e; --surface-2:#161b26; --raised:#1b212e;
    --line:#222a37; --line-2:#2e3848; --text:#eef1f7; --dim:#9aa6ba; --dim-2:#6b7689;
    --accent:#37c0e8; --accent-2:#7fe0ff; --accent-ink:#04141b;
    --crit:#ff6b6b; --crit-bg:#2a1316; --high:#ff9f43; --high-bg:#2a1d0f; --med:#f5c451; --med-bg:#272109; --low:#4fd18b; --low-bg:#0f2a1e;
    --r:14px; --r-sm:10px;
    --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Inter,Helvetica,Arial,sans-serif;
    --mono:"SF Mono","JetBrains Mono",ui-monospace,Menlo,Consolas,monospace;
  }
  *{box-sizing:border-box}
  body{margin:0;background:radial-gradient(1200px 600px at 50% -10%,var(--bg-grad),var(--bg)) fixed;color:var(--text);
    font-family:var(--sans);font-size:15px;line-height:1.55;-webkit-font-smoothing:antialiased}
  .wrap{max-width:680px;margin:0 auto;padding:0 20px 100px}
  a{color:var(--accent);text-decoration:none}

  /* top bar */
  .top{display:flex;align-items:center;gap:12px;padding:22px 0 8px}
  .brand{display:flex;align-items:center;gap:10px;font-weight:800;font-size:19px;letter-spacing:-.02em}
  .brand .mk{width:32px;height:32px;border-radius:9px;background:linear-gradient(145deg,var(--accent),#1f7fa0);
    display:flex;align-items:center;justify-content:center;box-shadow:0 4px 16px -4px var(--accent)}
  .brand .mk svg{width:18px;height:18px}
  .top .sp{flex:1}
  .wbtn{font-family:var(--sans);font-weight:600;font-size:13.5px;border-radius:10px;padding:9px 15px;border:1px solid var(--line-2);
    background:var(--surface-2);color:var(--text);cursor:pointer;transition:.15s;display:inline-flex;align-items:center;gap:8px}
  .wbtn:hover{border-color:var(--accent)}
  .wbtn.on{border-color:var(--low);color:var(--low)}
  .wbtn .dot{width:7px;height:7px;border-radius:50%;background:var(--low)}

  /* hero / scan */
  .hero{padding:14px 0 6px}
  .hero h1{font-size:clamp(24px,4.4vw,33px);font-weight:800;letter-spacing:-.03em;line-height:1.1;margin:0 0 8px}
  .hero p{color:var(--dim);margin:0 0 20px;max-width:52ch;font-size:15px}
  .scan{display:flex;gap:10px;background:var(--surface);border:1px solid var(--line);border-radius:var(--r);padding:8px;
    box-shadow:0 12px 40px -20px #000}
  .scan input{flex:1;min-width:0;background:transparent;border:none;outline:none;color:var(--text);
    font-family:var(--mono);font-size:14.5px;padding:11px 12px}
  .scan input::placeholder{color:var(--dim-2)}
  .scan button{font-family:var(--sans);font-weight:700;font-size:14px;border:none;border-radius:var(--r-sm);
    padding:11px 22px;background:var(--accent);color:var(--accent-ink);cursor:pointer;transition:.15s}
  .scan button:hover{background:var(--accent-2)}
  .scan button:disabled{opacity:.5;cursor:default}
  .micro{color:var(--dim-2);font-size:12.5px;margin:11px 2px 0;display:flex;align-items:center;gap:7px}
  .micro svg{width:13px;height:13px;flex:none}

  /* results */
  #out{margin-top:26px}
  .card{background:var(--surface);border:1px solid var(--line);border-radius:var(--r);overflow:hidden}
  .summary{padding:22px;display:flex;gap:22px;align-items:center;flex-wrap:wrap}
  .gauge{width:96px;height:96px;border-radius:50%;flex:none;display:flex;align-items:center;justify-content:center;position:relative}
  .gauge::after{content:"";position:absolute;inset:10px;border-radius:50%;background:var(--surface)}
  .gauge .v{position:relative;z-index:1;text-align:center}
  .gauge .v .n{font-weight:800;font-size:27px;line-height:1;font-variant-numeric:tabular-nums}
  .gauge .v .l{font-size:10px;color:var(--dim);margin-top:2px}
  .summ-main{flex:1;min-width:200px}
  .band{font-family:var(--mono);font-weight:800;font-size:12px;letter-spacing:.08em;padding:5px 11px;border-radius:20px;display:inline-block}
  .band.CRITICAL{color:var(--crit);background:var(--crit-bg)} .band.HIGH{color:var(--high);background:var(--high-bg)}
  .band.ELEVATED{color:var(--med);background:var(--med-bg)} .band.LOW{color:var(--low);background:var(--low-bg)}
  .summ-main .stats{display:flex;gap:18px;margin-top:12px;flex-wrap:wrap}
  .summ-main .st .n{font-weight:800;font-size:18px;font-variant-numeric:tabular-nums}
  .summ-main .st .n.risk{color:var(--high)}
  .summ-main .st .l{font-size:11.5px;color:var(--dim);margin-top:1px}

  /* 7702 banner */
  .deleg{margin-top:14px;border:1px solid var(--line);border-left:3px solid var(--med);background:var(--surface);border-radius:var(--r-sm);padding:15px 18px}
  .deleg.bad{border-left-color:var(--crit);background:linear-gradient(90deg,var(--crit-bg),var(--surface))}
  .deleg h3{margin:0 0 5px;font-size:14.5px;display:flex;align-items:center;gap:8px}
  .deleg p{margin:0;font-size:13px;color:var(--dim);line-height:1.5}
  .deleg code{font-family:var(--mono);font-size:12px;color:var(--text)}

  /* finding cards */
  .findings{margin-top:14px;display:flex;flex-direction:column;gap:10px}
  .fc{background:var(--surface);border:1px solid var(--line);border-left:3px solid var(--line-2);border-radius:var(--r-sm);
    padding:15px 18px;display:flex;gap:14px;align-items:flex-start;transition:.15s}
  .fc:hover{border-color:var(--line-2)}
  .fc.critical{border-left-color:var(--crit)} .fc.high{border-left-color:var(--high)}
  .fc.medium{border-left-color:var(--med)} .fc.low{border-left-color:var(--low)}
  .fc .ico{width:34px;height:34px;border-radius:9px;flex:none;display:flex;align-items:center;justify-content:center;
    font-family:var(--mono);font-weight:800;font-size:12px;background:var(--raised);color:var(--dim)}
  .fc.critical .ico{color:var(--crit);background:var(--crit-bg)} .fc.high .ico{color:var(--high);background:var(--high-bg)}
  .fc.medium .ico{color:var(--med);background:var(--med-bg)} .fc.low .ico{color:var(--low);background:var(--low-bg)}
  .fc .body{flex:1;min-width:0}
  .fc .hd{display:flex;align-items:center;gap:9px;flex-wrap:wrap}
  .fc .asset{font-weight:800;font-size:15px}
  .fc .sev{font-family:var(--mono);font-size:10px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;padding:2px 7px;border-radius:5px}
  .fc.critical .sev{color:var(--crit);background:var(--crit-bg)} .fc.high .sev{color:var(--high);background:var(--high-bg)}
  .fc.medium .sev{color:var(--med);background:var(--med-bg)} .fc.low .sev{color:var(--low);background:var(--low-bg)}
  .fc .spender{font-family:var(--mono);font-size:12px;color:var(--dim);margin-left:auto;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:200px}
  .fc .meta{display:flex;gap:12px;margin-top:4px;font-size:12px;color:var(--dim-2)}
  .fc .meta .risk{color:var(--high);font-weight:700;font-family:var(--mono)}
  .fc .reason{font-size:13px;color:var(--dim);margin-top:7px;line-height:1.5}
  .fc .rev{flex:none;align-self:center;font-family:var(--sans);font-weight:700;font-size:13px;border:1px solid var(--line-2);
    background:var(--raised);color:var(--text);border-radius:9px;padding:9px 16px;cursor:pointer;transition:.15s}
  .fc .rev:hover{border-color:var(--crit);color:var(--crit)}
  .fc .rev:disabled{cursor:default;opacity:.85}
  .fc .rev.done{border-color:var(--low);color:var(--low);background:var(--low-bg)}

  /* states */
  .state{text-align:center;padding:34px 22px;color:var(--dim)}
  .state.clean .big{font-size:40px} .state .big{font-size:30px}
  .state .t{font-weight:700;color:var(--text);margin:10px 0 4px;font-size:16px}
  .state .s{font-size:13.5px}
  .skel{height:90px;border-radius:var(--r);background:linear-gradient(100deg,var(--surface) 30%,var(--surface-2) 50%,var(--surface) 70%);
    background-size:200% 100%;animation:sh 1.2s linear infinite;margin-bottom:10px}
  @keyframes sh{to{background-position:-200% 0}}
  .note-box{font-size:12.5px;color:var(--dim);background:var(--surface-2);border:1px dashed var(--line-2);border-radius:var(--r-sm);padding:12px 15px;margin:14px 0}
  .note-box code{font-family:var(--mono);font-size:11.5px;color:var(--accent-2)}

  .foot{margin-top:30px;font-size:12px;color:var(--dim-2);line-height:1.6;text-align:center}
  .foot b{color:var(--dim)}

  /* toast */
  .toast{position:fixed;left:50%;bottom:26px;transform:translateX(-50%) translateY(16px);max-width:90%;
    background:var(--raised);border:1px solid var(--line-2);color:var(--text);font-size:13.5px;padding:13px 18px;
    border-radius:var(--r-sm);opacity:0;transition:.25s;pointer-events:none;box-shadow:0 16px 40px -16px #000;z-index:50}
  .toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
  .toast.warn{border-color:var(--high)} .toast.ok{border-color:var(--low)}
  .verdict-line{font-weight:600;font-size:14.5px;margin:9px 0 3px;color:var(--text)}
  .more{margin-top:12px;border:1px solid var(--line);border-radius:var(--r-sm);background:var(--surface);padding:0 16px}
  .more summary{cursor:pointer;padding:15px 0;color:var(--dim);font-weight:600;font-size:13.5px;list-style:none;user-select:none}
  .more summary::-webkit-details-marker{display:none}
  .more summary::before{content:"▸ ";color:var(--dim-2)}
  .more[open] summary::before{content:"▾ "}
  .more[open] summary{border-bottom:1px solid var(--line);margin-bottom:4px}
  .more .findings{padding-bottom:14px}
  @media (prefers-reduced-motion:reduce){.skel{animation:none}.toast{transition:none}}
  @media (max-width:560px){.fc{flex-wrap:wrap}.fc .rev{width:100%}.fc .spender{max-width:none}}
</style></head><body><div class="wrap">

  <div class="top">
    <div class="brand"><span class="mk"><svg viewBox="0 0 24 24" fill="none"><path d="M12 2l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5l8-3z" fill="#04141b" stroke="#fff" stroke-width="1.5" stroke-linejoin="round"/><path d="M8.5 12l2.5 2.5 4.5-5" stroke="#fff" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"/></svg></span>Sentinel</div>
    <div class="sp"></div>
    <button class="wbtn" id="connect">Connect wallet</button>
  </div>

  <div class="hero">
    <h1>See everything that can drain your wallet.</h1>
    <p>Risky token approvals, hidden Permit2 allowances, and malicious EIP-7702 delegations — ranked by real dollars at risk. Read-only &amp; non-custodial.</p>
    <div class="scan">
      <input id="addr" placeholder="Paste a 0x address, or connect your wallet" spellcheck="false" autocomplete="off">
      <button id="scan">Scan</button>
    </div>
    <div class="micro"><svg viewBox="0 0 24 24" fill="none"><path d="M12 2l7 3v6c0 4.5-3 7.5-7 9.5-4-2-7-5-7-9.5V5l7-3z" stroke="#6b7689" stroke-width="1.6"/></svg> We never request spending permission — connecting only reads your address.</div>
  </div>

  <div id="out"></div>

  <div class="foot">Sentinel reads public on-chain data. Scanning is free. Revoking is a transaction <b>you</b> sign and pay gas for — Sentinel holds no keys, moves no funds, and takes no fee.</div>
</div>
<div class="toast" id="toast"></div>

<script>
const $=id=>document.getElementById(id), out=$('out'), addrEl=$('addr');
let scanned=null, connected=null;
const ESC=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const short=a=>a?a.slice(0,6)+'…'+a.slice(-4):'';
function toast(msg,kind){const t=$('toast');t.className='toast show '+(kind||'');t.textContent=msg;clearTimeout(t._h);t._h=setTimeout(()=>t.className='toast',3800);}

// ---- wallet connect ----
$('connect').onclick=async()=>{
  if(!window.ethereum){toast('No browser wallet found. Install MetaMask (or similar) to connect & revoke.','warn');return;}
  try{
    const accs=await window.ethereum.request({method:'eth_requestAccounts'});
    connected=(accs[0]||'').toLowerCase();
    const b=$('connect');b.classList.add('on');b.innerHTML='<span class="dot"></span>'+short(connected);
    addrEl.value=connected;scan();
  }catch(e){toast('Wallet connection cancelled.','warn');}
};

// ---- scan ----
$('scan').onclick=scan;
addrEl.addEventListener('keydown',e=>{if(e.key==='Enter')scan();});
async function scan(){
  const a=addrEl.value.trim();
  if(!/^0x[0-9a-fA-F]{40}$/.test(a)){toast('Enter a valid 0x address.','warn');return;}
  scanned=a;
  out.innerHTML='<div class="skel"></div><div class="skel" style="height:64px"></div><div class="skel" style="height:64px"></div>';
  $('scan').disabled=true;
  try{
    const res=await fetch('/api/scan?address='+a);const j=await res.json();
    if(j.error){out.innerHTML='<div class="card"><div class="state"><div class="big">⚠️</div><div class="t">'+ESC(j.error)+'</div></div></div>';return;}
    render(j.report,j.source);
  }catch(e){out.innerHTML='<div class="card"><div class="state"><div class="big">⚠️</div><div class="t">Network error</div><div class="s">'+ESC(e.message||e)+'</div></div></div>';}
  finally{$('scan').disabled=false;}
}

// ---- render ----
function fcard(f){
  const a=f.approval, sp=a.spender.label||short(a.spender.address);
  const risk=a.exposureUsd>0?'<span class="risk">$'+Math.round(a.exposureUsd).toLocaleString()+' exposed</span>':'';
  const btn=f.revoke?'<button class="rev" data-to="'+ESC(f.revoke.to)+'" data-data="'+ESC(f.revoke.data)+'">Revoke</button>':'';
  return '<div class="fc '+f.level+'"><div class="ico">'+f.level[0].toUpperCase()+'</div>'+
    '<div class="body"><div class="hd"><span class="asset">'+ESC(a.asset)+'</span><span class="sev">'+f.level+'</span><span class="spender">'+ESC(sp)+'</span></div>'+
    '<div class="meta"><span>['+ESC(a.allowance)+']</span>'+risk+'</div>'+
    '<div class="reason">'+ESC(f.reason)+'</div></div>'+btn+'</div>';
}
function delegHtml(r){
  if(!(r.delegation&&r.delegation.delegated))return '';
  const bad=r.delegation.malicious;
  return '<div class="deleg'+(bad?' bad':'')+'"><h3>'+(bad?'🚨 Malicious EIP-7702 delegation':'⚠️ EIP-7702 delegation present')+'</h3>'+
    '<p>Your account delegates its code to <code>'+ESC(short(r.delegation.delegate||''))+'</code>'+(r.delegation.delegateLabel?' ('+ESC(r.delegation.delegateLabel)+')':'')+'. '+
    (bad?'Reset it to the zero address from your wallet immediately.':'Normal for smart-account wallets — we checked it and it is not flagged malicious; confirm it matches your wallet provider.')+'</p></div>';
}
function render(r,source){
  const appr=r.findings.filter(f=>f.approval.kind!=='delegation');

  // Couldn't read approvals → never show a (false) clean score. Lead with the state.
  if(source==='unavailable'){
    out.innerHTML='<div class="card"><div class="state"><div class="big">🔌</div><div class="t">Couldn\\'t read this wallet\\'s approvals</div>'+
      '<div class="s">The approval data source needs a free Etherscan key (set <code>ETHERSCAN_KEY</code>). The delegation check below is live.</div></div>'+delegHtml(r)+'</div>';
    return;
  }

  const important=appr.filter(f=>f.level==='critical'||f.level==='high');
  const routine=appr.filter(f=>f.level==='medium'||f.level==='low');

  let verdict;
  if(r.counts.critical>0) verdict='⚠️ '+r.counts.critical+' critical issue'+(r.counts.critical>1?'s':'')+' need your attention.';
  else if(r.delegation&&r.delegation.malicious) verdict='⚠️ Malicious account delegation detected.';
  else if(r.counts.high>0) verdict=r.counts.high+' approval'+(r.counts.high>1?'s':'')+' worth reviewing.';
  else if(appr.length) verdict='✓ No critical issues — '+appr.length+' routine approval'+(appr.length>1?'s':'')+'.';
  else verdict='✓ No approvals found — nothing to revoke.';

  const gaugeColor=r.band==='CRITICAL'?'var(--crit)':r.band==='HIGH'?'var(--high)':r.band==='ELEVATED'?'var(--med)':'var(--low)';
  let h='<div class="card"><div class="summary">'+
    '<div class="gauge" style="background:conic-gradient('+gaugeColor+' '+r.score+'%,var(--line) 0)"><div class="v"><div class="n">'+r.score+'</div><div class="l">/ 100</div></div></div>'+
    '<div class="summ-main"><span class="band '+r.band+'">'+r.band+'</span>'+
      '<div class="verdict-line">'+verdict+'</div>'+
      '<div class="stats">'+
        '<div class="st"><div class="n risk">$'+Math.round(r.atRiskUsd).toLocaleString()+'</div><div class="l">total exposure</div></div>'+
        '<div class="st"><div class="n" style="color:var(--crit)">'+r.counts.critical+'</div><div class="l">critical</div></div>'+
        '<div class="st"><div class="n" style="color:var(--high)">'+r.counts.high+'</div><div class="l">high</div></div>'+
        '<div class="st"><div class="n">'+routine.length+'</div><div class="l">routine</div></div>'+
      '</div></div></div>'+delegHtml(r)+'</div>';

  if(source==='demo')h+='<div class="note-box">Sample data — illustrative, not a real wallet.</div>';

  if(important.length) h+='<div class="findings">'+important.map(fcard).join('')+'</div>';
  if(routine.length) h+='<details class="more"><summary>Show '+routine.length+' routine / low-risk approval'+(routine.length>1?'s':'')+' &nbsp;($'+Math.round(routine.reduce((s,f)=>s+f.approval.exposureUsd,0)).toLocaleString()+')</summary><div class="findings" style="margin-top:10px">'+routine.map(fcard).join('')+'</div></details>';
  if(!appr.length&&(source==='clean'||source==='live')) h+='<div class="card"><div class="state clean"><div class="big">✅</div><div class="t">No open approvals found</div><div class="s">This wallet has no token approvals to revoke.</div></div></div>';
  out.innerHTML=h;
}

// ---- revoke (delegated, robust) ----
out.addEventListener('click',async e=>{
  const b=e.target.closest('.rev'); if(!b) return;
  if(!window.ethereum){toast('Install a browser wallet (e.g. MetaMask) and connect the account that owns this wallet to revoke.','warn');return;}
  try{
    const accs=await window.ethereum.request({method:'eth_requestAccounts'});
    const from=(accs[0]||'').toLowerCase();
    if(scanned&&from!==scanned.toLowerCase()){
      toast('To revoke, connect the wallet that owns '+short(scanned)+'. You\\'re connected as '+short(from)+'.','warn');
      return;
    }
    const old=b.textContent;b.disabled=true;b.textContent='Confirm in wallet…';
    try{
      await window.ethereum.request({method:'eth_sendTransaction',params:[{from,to:b.dataset.to,data:b.dataset.data}]});
      b.textContent='Revoked ✓';b.classList.add('done');toast('Revoke submitted — it will clear once the transaction confirms.','ok');
    }catch(err){b.disabled=false;b.textContent=old;toast('Revoke cancelled or failed: '+(err.message||err),'warn');}
  }catch(err){toast('Could not access wallet: '+(err.message||err),'warn');}
});
</script></body></html>`;
