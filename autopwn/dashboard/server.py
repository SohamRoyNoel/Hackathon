"""Local web dashboard for autopwn / detpwn results. Zero dependencies (stdlib).

    autopwn-dash                 # serve ./ (and parents) at http://127.0.0.1:8765
    autopwn-dash --root DIR --port 9000 --no-open
"""
from __future__ import annotations

import argparse
import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import parse

PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>autopwn results</title>
<style>
:root{
  --bg:#111110; --surface:#1a1a19; --panel:#232322; --panel2:#2b2b29;
  --ink:#ffffff; --ink2:#c3c2b7; --muted:#86857c; --border:#383835;
  --good:#0ca30c; --warning:#fab219; --serious:#ec835a; --critical:#d03b3b;
  --accent:#3987e5;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:14px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
a{color:var(--accent)}
header{position:sticky;top:0;z-index:5;background:var(--surface);
  border-bottom:1px solid var(--border);padding:14px 22px;display:flex;
  align-items:center;gap:14px}
header h1{font-size:16px;margin:0;letter-spacing:.3px}
header .sub{color:var(--muted);font-size:12px}
header .spacer{flex:1}
button{font:inherit;color:var(--ink);background:var(--panel);
  border:1px solid var(--border);border-radius:8px;padding:6px 12px;cursor:pointer}
button:hover{background:var(--panel2)}
.wrap{max-width:1100px;margin:0 auto;padding:22px}
.kpis{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:20px}
.tile{background:var(--surface);border:1px solid var(--border);border-radius:12px;
  padding:16px}
.tile .n{font-size:30px;font-weight:650;line-height:1}
.tile .l{color:var(--muted);font-size:12px;margin-top:6px;text-transform:uppercase;
  letter-spacing:.5px}
.tile.good .n{color:var(--good)} .tile.warn .n{color:var(--warning)}
.controls{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px;align-items:center}
.controls input,.controls select{font:inherit;color:var(--ink);background:var(--panel);
  border:1px solid var(--border);border-radius:8px;padding:6px 10px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;
  margin-bottom:12px;overflow:hidden;display:flex}
.card .stripe{width:5px;flex:none}
.card .body{padding:14px 16px;flex:1;min-width:0}
.card .row1{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.host{font-weight:650;font-size:15px}
.chip{font-size:11px;padding:2px 8px;border-radius:999px;border:1px solid var(--border);
  color:var(--ink2);background:var(--panel)}
.chip.tool{text-transform:lowercase}
.badge{font-size:11px;font-weight:650;padding:3px 9px;border-radius:999px;
  display:inline-flex;gap:5px;align-items:center}
.badge.root{color:#071;background:rgba(12,163,12,.16);border:1px solid var(--good)}
.badge.flags{color:#8a5e00;background:rgba(250,178,25,.16);border:1px solid var(--warning)}
.badge.none{color:#fff;background:rgba(208,59,59,.16);border:1px solid var(--critical)}
.badge.root{color:#7fe08a}.badge.flags{color:#ffcf6b}.badge.none{color:#f1a1a1}
.ts{color:var(--muted);font-size:12px;margin-left:auto}
.meta{color:var(--ink2);font-size:13px;margin-top:8px;display:flex;gap:18px;flex-wrap:wrap}
.chain{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-top:8px}
.node{font-size:11px;padding:2px 8px;border-radius:6px;background:var(--panel2);
  border:1px solid var(--border)}
.arrow{color:var(--muted)}
.flags{margin-top:8px;display:flex;gap:6px;flex-wrap:wrap}
.flag{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;color:#7fe08a;
  background:rgba(12,163,12,.1);border:1px solid rgba(12,163,12,.4);
  border-radius:6px;padding:2px 8px}
.tile.crit .n{color:var(--critical)} .tile.high .n{color:var(--serious)}
.sevrow{display:flex;gap:12px;flex-wrap:wrap;margin-top:8px;align-items:center}
.sevcount{font-size:11px;color:var(--ink2);display:inline-flex;gap:5px;align-items:center}
.sevdot{width:9px;height:9px;border-radius:50%}
.sev{font-size:10px;font-weight:700;padding:2px 8px;border-radius:999px;
  display:inline-flex;gap:5px;align-items:center;border:1px solid;white-space:nowrap}
.danger{margin-top:10px;font-size:12.5px;color:#f1a1a1;background:rgba(208,59,59,.1);
  border:1px solid rgba(208,59,59,.4);border-radius:8px;padding:7px 11px;
  display:flex;gap:8px;align-items:flex-start;line-height:1.45}
.statustag{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.4px}
.finding{display:flex;gap:10px;align-items:center;padding:7px 0;border-bottom:1px solid var(--border)}
.finding .t{flex:1;min-width:0}
.highlights{background:var(--surface);border:1px solid var(--critical);border-left-width:4px;
  border-radius:12px;padding:14px 16px;margin-bottom:20px}
.highlights h2{font-size:12px;margin:0 0 10px;color:#f1a1a1;text-transform:uppercase;letter-spacing:.6px}
.highlights .hitem{display:flex;gap:10px;align-items:center;padding:4px 0;font-size:13px}
.highlights .hhost{color:var(--muted);font-size:12px;margin-left:auto}
.dots{display:inline-flex;gap:3px;vertical-align:middle;margin-left:8px}
.dot{width:8px;height:8px;border-radius:2px;background:var(--muted)}
.dot.ok{background:var(--good)}
.empty{color:var(--muted);text-align:center;padding:40px}
dialog{background:var(--surface);color:var(--ink);border:1px solid var(--border);
  border-radius:14px;max-width:820px;width:92%;padding:0}
dialog::backdrop{background:rgba(0,0,0,.6)}
.dlg-head{display:flex;align-items:center;gap:12px;padding:16px 20px;
  border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--surface)}
.dlg-body{padding:18px 20px;max-height:70vh;overflow:auto}
.dlg-body h3{margin:18px 0 8px;font-size:13px;color:var(--muted);
  text-transform:uppercase;letter-spacing:.5px}
.att{font:12px ui-monospace,Menlo,monospace;padding:3px 0;border-bottom:1px solid var(--border)}
.att .m{display:inline-block;width:16px;font-weight:700}
.att.ok .m{color:var(--good)} .att.no .m{color:var(--critical)}
pre{background:var(--bg);border:1px solid var(--border);border-radius:8px;
  padding:12px;overflow:auto;font:12px ui-monospace,Menlo,monospace;color:var(--ink2)}
.md h4{margin:14px 0 6px} .md code{background:var(--bg);padding:1px 5px;border-radius:4px;
  font-family:ui-monospace,Menlo,monospace;color:#ffcf6b} .md li{margin:2px 0}
</style></head>
<body>
<header>
  <h1>🛡️ autopwn <span style="color:var(--muted)">results</span></h1>
  <span class="sub" id="sub"></span>
  <span class="spacer"></span>
  <button onclick="load()">↻ Refresh</button>
</header>
<div class="wrap">
  <div class="kpis" id="kpis"></div>
  <div class="highlights" id="highlights" style="display:none"></div>
  <div class="controls">
    <input id="q" placeholder="Search host…" oninput="render()">
    <select id="tool" onchange="render()"><option value="">All tools</option>
      <option value="detpwn">detpwn</option><option value="autopwn">autopwn</option></select>
    <select id="status" onchange="render()"><option value="">All status</option>
      <option value="root">Root achieved</option><option value="flags">Flags only</option>
      <option value="none">No access</option></select>
  </div>
  <div id="list"></div>
</div>
<dialog id="dlg"><div class="dlg-head"><strong id="dlg-title"></strong>
  <span class="spacer" style="flex:1"></span>
  <button onclick="document.getElementById('dlg').close()">✕ Close</button></div>
  <div class="dlg-body" id="dlg-body"></div></dialog>
<script>
let DATA={summary:{},engagements:[]};
const ST={root:{c:'root',i:'✓',l:'ROOT'},flags:{c:'flags',i:'⚑',l:'FLAGS'},
          none:{c:'none',i:'✗',l:'NO ACCESS'}};
const STRIPE={root:'var(--good)',flags:'var(--warning)',none:'var(--critical)'};
const SEV={critical:{c:'#d03b3b',l:'CRITICAL'},high:{c:'#ec835a',l:'HIGH'},
           medium:{c:'#fab219',l:'MEDIUM'},low:{c:'#86857c',l:'LOW'}};
const STAT={exploited:'💥 exploited',attempted:'○ attempted',identified:'◦ identified'};
const esc=s=>(s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
function sevBadge(sev){const s=SEV[sev]||SEV.medium;
  return `<span class="sev" style="color:${s.c};border-color:${s.c};background:${s.c}22">${s.l}</span>`}
function sevRow(sc){return ['critical','high','medium','low'].filter(k=>sc[k])
  .map(k=>`<span class="sevcount"><span class="sevdot" style="background:${SEV[k].c}"></span>${sc[k]} ${k}</span>`).join('');}

function mdRender(s){
  const out=[];let inList=false;
  for(let line of (s||'').split('\n')){
    let l=esc(line);
    l=l.replace(/`([^`]+)`/g,'<code>$1</code>').replace(/\*\*([^*]+)\*\*/g,'<strong>$1</strong>');
    if(/^###\s/.test(line)){if(inList){out.push('</ul>');inList=false}out.push('<h4>'+l.replace(/^###\s*/,'')+'</h4>')}
    else if(/^\s*-\s/.test(line)){if(!inList){out.push('<ul>');inList=true}out.push('<li>'+l.replace(/^\s*-\s*/,'')+'</li>')}
    else if(line.trim()===''){if(inList){out.push('</ul>');inList=false}}
    else out.push('<div>'+l+'</div>');
  }
  if(inList)out.push('</ul>');
  return out.join('');
}

function kpi(n,l,cls){return `<div class="tile ${cls||''}"><div class="n">${n}</div><div class="l">${l}</div></div>`}
function renderKpis(s){document.getElementById('kpis').innerHTML=
  kpi(s.total||0,'Engagements')+kpi(s.roots||0,'Root achieved','good')+
  kpi(s.unique_flags||0,'Flags exposed','warn')+kpi(s.critical||0,'Critical findings','crit')+
  kpi(s.high||0,'High findings','high')+kpi(s.exploited||0,'Exploited');}

function renderHighlights(engs){
  const items=[];
  for(const e of engs) if(e.status==='root')
    items.push({severity:'critical',title:'Full root compromise achieved',host:e.host,tool:e.tool,root:true});
  for(const e of engs) for(const f of e.exploited)
    if(f.severity==='critical'||f.severity==='high')
      items.push({...f,host:e.host,tool:e.tool});
  for(const e of engs) for(const fl of e.flags)
    items.push({severity:'high',title:'Sensitive data exposed: '+fl,host:e.host,tool:e.tool,flag:true});
  const box=document.getElementById('highlights');
  if(!items.length){box.style.display='none';return;}
  items.sort((a,b)=>({critical:0,high:1}[a.severity]-{critical:0,high:1}[b.severity]));
  box.style.display='';
  box.innerHTML='<h2>⚠ Dangerous activity — exploited &amp; exposed</h2>'+
    items.slice(0,10).map(f=>`<div class="hitem">${sevBadge(f.severity)}
      <span>${f.flag?'🏳 ':'💥 '}${esc(f.title)}</span>
      <span class="hhost">${esc(f.host)} · ${f.tool}</span></div>`).join('');
}

function chain(users){if(!users||!users.length)return '';
  return '<div class="chain">'+users.map(u=>`<span class="node">${esc(u)}</span>`)
    .join('<span class="arrow">→</span>')+'</div>';}

function dangerBox(e){
  const parts=[];
  if(e.status==='root') parts.push('full root compromise');
  e.exploited.filter(f=>f.severity==='critical'||f.severity==='high')
    .forEach(f=>parts.push(esc(f.title)));
  if(e.flags.length) parts.push(e.flags.length+' flag'+(e.flags.length>1?'s':'')+' exposed');
  if(!parts.length) return '';
  return `<div class="danger">⚠<span><strong>Exploited:</strong> ${parts.join(' · ')}</span></div>`;
}
function dots(att){const t=att.length,ok=att.filter(a=>a.ok).length;
  let d='';for(let i=0;i<Math.min(t,24);i++)d+=`<span class="dot ${att[i].ok?'ok':''}"></span>`;
  return `${ok}/${t} vectors succeeded<span class="dots">${d}</span>`;}

function render(){
  const q=document.getElementById('q').value.toLowerCase();
  const ft=document.getElementById('tool').value, fs=document.getElementById('status').value;
  const items=DATA.engagements.filter(e=>
    (!q||e.host.toLowerCase().includes(q))&&(!ft||e.tool===ft)&&(!fs||e.status===fs));
  const list=document.getElementById('list');
  if(!items.length){list.innerHTML='<div class="empty">No engagements match.</div>';return;}
  list.innerHTML=items.map((e,i)=>{const s=ST[e.status];
    return `<div class="card" onclick="openDlg(${DATA.engagements.indexOf(e)})" style="cursor:pointer">
      <div class="stripe" style="background:${STRIPE[e.status]}"></div>
      <div class="body">
        <div class="row1"><span class="host">${esc(e.host)}</span>
          <span class="chip tool">${e.tool}</span>
          <span class="badge ${s.c}">${s.i} ${s.l}</span>
          <span class="ts">${esc(e.timestamp.replace('T',' '))}</span></div>
        <div class="meta"><span>${esc(e.result)}</span>
          ${e.attempt_count?`<span>${dots(e.attempts)}</span>`:''}</div>
        ${sevRow(e.sev_counts)?`<div class="sevrow">${sevRow(e.sev_counts)}</div>`:''}
        ${chain(e.users)}
        ${dangerBox(e)}
        ${e.flags.length?`<div class="flags">${e.flags.map(f=>`<span class="flag">${esc(f)}</span>`).join('')}</div>`:''}
      </div></div>`;}).join('');
}

function openDlg(idx){const e=DATA.engagements[idx];const s=ST[e.status];
  document.getElementById('dlg-title').innerHTML=`${esc(e.host)} · <span class="chip tool">${e.tool}</span> <span class="badge ${s.c}">${s.i} ${s.l}</span>`;
  const att=e.attempts.map(a=>`<div class="att ${a.ok?'ok':'no'}"><span class="m">${a.ok?'+':'−'}</span>${esc(a.text)}</div>`).join('')||'<div class="att">—</div>';
  document.getElementById('dlg-body').innerHTML=
    `<h3>Result</h3><div>${esc(e.result)}</div>`+
    (e.users.length?`<h3>Escalation chain</h3>${chain(e.users)}`:'')+
    `<h3>Flags (${e.flags.length})</h3>`+(e.flags.length?`<div class="flags">${e.flags.map(f=>`<span class="flag">${esc(f)}</span>`).join('')}</div>`:'<div>(none)</div>')+
    `<h3>Findings (${e.findings.length})</h3>`+(e.findings.length?e.findings.map(f=>
      `<div class="finding">${sevBadge(f.severity)}<span class="t">${esc(f.title)}${f.user?` <span class="statustag">as ${esc(f.user)}</span>`:''}</span><span class="statustag">${STAT[f.status]||f.status}</span></div>`).join(''):'<div>(none)</div>')+
    `<h3>Attempts (${e.attempt_count})</h3>${att}`+
    (e.analysis?`<h3>Analysis</h3><div class="md">${mdRender(e.analysis)}</div>`:'')+
    `<h3>Full report</h3><pre>${esc(e.raw)}</pre>`;
  document.getElementById('dlg').showModal();
}

async function load(){const r=await fetch('/api/data');DATA=await r.json();
  renderKpis(DATA.summary);
  renderHighlights(DATA.engagements);
  document.getElementById('sub').textContent=DATA.root;
  render();}
load();
</script></body></html>
"""


class Handler(BaseHTTPRequestHandler):
    root: Path = Path(".")

    def log_message(self, *a):  # quiet
        pass

    def _send(self, code, body, ctype):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/index"):
            self._send(200, PAGE, "text/html; charset=utf-8")
        elif self.path.startswith("/api/data"):
            engagements = parse.discover(self.root)
            payload = {
                "root": str(self.root),
                "summary": parse.summarize(engagements),
                "engagements": engagements,
            }
            self._send(200, json.dumps(payload), "application/json")
        else:
            self._send(404, "not found", "text/plain")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="autopwn-dash", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--root", default=None,
                   help="directory to scan for engagements (default: repo root)")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--no-open", action="store_true", help="don't open a browser")
    args = p.parse_args(argv)

    root = Path(args.root).resolve() if args.root else Path(__file__).resolve().parents[2]
    Handler.root = root
    n = len(parse.discover(root))
    url = f"http://127.0.0.1:{args.port}/"
    print(f"[*] autopwn dashboard scanning: {root}")
    print(f"[*] {n} engagement(s) found")
    print(f"[*] serving at {url}  (Ctrl-C to stop)")
    if not args.no_open:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
