#!/usr/bin/env python3
"""Build dashboards/a3e_v2_dashboard.html (self-contained; data and figures embedded)."""
import os, sys, json, base64, glob
import pandas as pd
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "src"))
from a3e_dns_v2 import params, traffic as T
tab = lambda n: pd.read_csv(os.path.join(ROOT, "results_v2", "tables", n + ".csv"))
def recs(df): return json.loads(df.round(4).to_json(orient="records"))
data = {n: recs(tab(n)) for n in ["e1_per_scenario_protocol", "e1_severity_sweep", "e9_pgd_robustness", "e9_evasion_blend", "e2_byzantine_sweep", "e3_dp_sweep", "e3_dp_calibration_grid",
        "e4_noise_growth", "e4_operation_latency", "e4_selective_operations", "e4_encrypted_histogram", "e5_side_channel_tradeoff", "e5_sigma_vs_kl", "e6_factorial_ablation",
        "e7_policy_sensitivity", "e7_policy_rollouts", "e8_intel_fusion", "e10_case_matrix_wide", "e10_attack_case_matrix"]}
data["registry"] = [dict(key=p.key, value=p.value, source=p.section, component=p.component, status=p.status, note=p.note) for p in params.REGISTRY]
data["scenarios"] = [dict(id=s.sid, protocol=s.protocol, family=s.family, description=s.description, shifts="; ".join(f"{k} {'+' if v > 0 else '-'}{abs(v)}" for k, v in s.shift.items())) for s in T.SCENARIOS.values()]
data["thesis33"] = [dict(metric=m, dnsguard=a, deepfingerprint=b, a3e=c) for m, a, b, c in [("Accuracy (%)", 91.2, 96.7, 99.94), ("FPR (%)", 2.1, 0.8, 0.17), ("P99 latency (ms)", 4.2, 2.8, 1.42), ("Throughput (M QPS)", 8, 15, 22.5), ("Adversarial robustness (%)", 65, 82, 96.5)]]
data["thesis32"] = [dict(id=i, tool=t, response_ms=r, success=s, fnr=f) for i, t, r, s, f in [("S1-Timing", "tshark + custom", 0.4, 98.7, 1.3), ("S2-Tunnel", "dnscat2", 1.2, 99.2, 0.8), ("S3-Poison", "fl-attack", 2.5, 96.5, 3.5), ("S4-Quantum", "liboqs", 1.8, 100.0, 0.0), ("S5-Evasion", "ART", 0.9, 97.8, 2.2)]]
data["audit"] = [dict(id=i, item=a, s1=b, s2=c) for i, a, b, c in [
 ("A1", "QHE ring parameters", "Table 27: dim 1024, modulus 3329", "Table 34a: n = 256, q = 4096"), ("A2", "SIMD slots", "6.5.1: 1,024 slots", "Table 34a: n = 256"),
 ("A3", "DP epsilon", "6.6.5, Table 33: 0.68", "Tables 27 and 30: 0.7"), ("A4", "DP noise", "6.6.5: Gaussian", "Table 27: Lap(0.1/0.7); Table 31: N(0, 0.5)"),
 ("A5", "AEE latency", "Table 27: about 0.2 ms", "6.17.2: about 0.8 ms (whole layer)"), ("A6", "Throughput", "Table 33: 22.5 M QPS", "6.15.1: 30 M QPS load"),
 ("A7", "Entropy source", "6.4.3: RDRAND/RDSEED + system", "Table 27 command: /dev/urandom"), ("A8", "S3 malicious updates", "Table 32: 7", "Table 31: 5 clients"),
 ("A9", "S5 epsilon", "Table 32: 0.15", "Table 30: 0.3"), ("A10", "Adversarial robustness 96.5 %", "Table 33", "6.16: S3 rate; S5 is 97.8 %")]]
figs = {os.path.basename(f)[:-4]: base64.b64encode(open(f, "rb").read()).decode() for f in sorted(glob.glob(os.path.join(ROOT, "results_v2", "figures", "*.png")))}
meta = json.load(open(os.path.join(ROOT, "results_v2", "run_metadata.json")))

HTML = r"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>A3E-DNS v2 extended results</title>
<style>
:root{--bg:#fff;--fg:#1d2430;--mut:#5b6677;--card:#f5f7fa;--bd:#d9dee6;--ac:#1f5fbf;--ok:#1a7f4b;--wn:#b25e00;--bad:#b3261e;--syn:#fff4e0;--th:#e8f1ff}
@media (prefers-color-scheme:dark){:root{--bg:#10151c;--fg:#e6ebf2;--mut:#9aa6b8;--card:#18202a;--bd:#2c3745;--ac:#6ea8ff;--ok:#5fd39a;--wn:#ffb454;--bad:#ff8a80;--syn:#2b2312;--th:#14243b}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
header{padding:20px 24px 8px}h1{margin:0 0 4px;font-size:22px}header p{margin:0;color:var(--mut)}
nav{display:flex;flex-wrap:wrap;gap:6px;padding:8px 24px;border-bottom:1px solid var(--bd);position:sticky;top:0;background:var(--bg);z-index:5}
nav button{border:1px solid var(--bd);background:var(--card);color:var(--fg);padding:6px 12px;border-radius:6px;cursor:pointer;font:inherit}
nav button.on{background:var(--ac);color:#fff;border-color:var(--ac)}
main{padding:16px 24px 48px;max-width:1280px;margin:auto}section{display:none}section.on{display:block}
.banner{padding:10px 14px;border-radius:8px;margin:10px 0 16px;border:1px solid var(--bd);font-size:14px}
.syn{background:var(--syn)}.thr{background:var(--th)}
h2{font-size:18px;margin:22px 0 8px}.grid{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(260px,1fr))}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:12px 14px}.card b{display:block;font-size:24px}
.tw{overflow-x:auto;border:1px solid var(--bd);border-radius:8px;margin:8px 0}table{border-collapse:collapse;width:100%;font-size:13px}
th,td{padding:6px 10px;border-bottom:1px solid var(--bd);text-align:left;white-space:nowrap}th{background:var(--card);cursor:pointer;position:sticky;top:0}
td.n{text-align:right;font-variant-numeric:tabular-nums}.tag{padding:1px 8px;border-radius:10px;font-size:12px;border:1px solid var(--bd)}.conflict{color:var(--bad);border-color:var(--bad)}
select,input{background:var(--card);color:var(--fg);border:1px solid var(--bd);border-radius:6px;padding:5px 8px;font:inherit}.row{display:flex;gap:10px;flex-wrap:wrap;margin:8px 0}
svg text{fill:var(--mut);font-size:11px}.legend span{margin-right:12px;font-size:12px}.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:4px}
img{max-width:100%;border:1px solid var(--bd);border-radius:8px;background:#fff}.heat{display:grid;gap:2px;font-size:12px}.heat div{padding:5px 6px;text-align:center;border-radius:3px}
small{color:var(--mut)}code{background:var(--card);padding:1px 5px;border-radius:4px}
</style></head><body>
<header><h1>A3E-DNS v2: extended results and specifications</h1><p>Chapter 6, Next-Generation Secure Encrypted DNS Architectures. Reproducibility package, version 2.</p></header>
<nav id="nav"></nav><main id="main"></main>
<script>
const D=__DATA__, FIGS=__FIGS__, META=__META__;
const COLORS=['#1f5fbf','#d1495b','#2a9d8f','#e9a23b','#7b4fd1','#5b6677'];
const $=(s,r=document)=>r.querySelector(s), el=(t,a={},h='')=>{const e=document.createElement(t);for(const k in a)e.setAttribute(k,a[k]);e.innerHTML=h;return e};
const fmt=v=>typeof v==='number'?(Number.isInteger(v)?String(v):(Math.abs(v)<0.001&&v!==0?v.toExponential(2):v.toFixed(Math.abs(v)>=100?1:3))):(v===null?'':v);
function table(rows,cols,opts={}){cols=cols||Object.keys(rows[0]||{});const w=el('div',{class:'tw'}),t=el('table');let state=rows.slice(),dir=1,last=null;
 const head=()=>{t.innerHTML='';const tr=el('tr');cols.forEach(c=>{const th=el('th',{},c+(last===c?(dir>0?' ▲':' ▼'):''));th.onclick=()=>{dir=last===c?-dir:1;last=c;state.sort((a,b)=>(a[c]>b[c]?1:a[c]<b[c]?-1:0)*dir);head()};tr.appendChild(th)});t.appendChild(tr);
  state.forEach(r=>{const tr=el('tr');cols.forEach(c=>{const v=r[c];const td=el('td',{class:typeof v==='number'?'n':''},c==='status'&&v==='conflict'?'<span class="tag conflict">conflict</span>':fmt(v));tr.appendChild(td)});t.appendChild(tr)})};head();w.appendChild(t);return w}
function lineChart(series,{xl='',yl='',w=640,h=300,logx=false,logy=false,xs=null}={}){const m={l:52,r:14,t:14,b:42};const all=series.flatMap(s=>s.pts);const X=all.map(p=>p[0]),Y=all.map(p=>p[1]);
 const f=(v,l)=>l?Math.log10(Math.max(v,1e-9)):v;let x0=Math.min(...X.map(v=>f(v,logx))),x1=Math.max(...X.map(v=>f(v,logx))),y0=Math.min(...Y.map(v=>f(v,logy))),y1=Math.max(...Y.map(v=>f(v,logy)));
 if(y0===y1){y0-=.5;y1+=.5}const pad=(y1-y0)*.06;y0-=pad;y1+=pad;if(x0===x1){x0-=.5;x1+=.5}
 const sx=v=>m.l+(f(v,logx)-x0)/(x1-x0)*(w-m.l-m.r),sy=v=>h-m.b-(f(v,logy)-y0)/(y1-y0)*(h-m.t-m.b);let s=`<svg viewBox="0 0 ${w} ${h}" width="100%" role="img">`;
 for(let i=0;i<=4;i++){const yv=y0+(y1-y0)*i/4,py=h-m.b-(h-m.t-m.b)*i/4;s+=`<line x1="${m.l}" x2="${w-m.r}" y1="${py}" y2="${py}" stroke="var(--bd)"/><text x="${m.l-6}" y="${py+4}" text-anchor="end">${logy?(10**yv).toPrecision(2):yv.toFixed(2)}</text>`}
 const xt=xs||[...new Set(X)].sort((a,b)=>a-b);const step=Math.ceil(xt.length/8);xt.forEach((v,i)=>{if(i%step===0)s+=`<text x="${sx(v)}" y="${h-m.b+16}" text-anchor="middle">${fmt(v)}</text>`});
 s+=`<text x="${(w+m.l)/2}" y="${h-6}" text-anchor="middle">${xl}</text><text transform="translate(12 ${h/2}) rotate(-90)" text-anchor="middle">${yl}</text>`;
 series.forEach((se,i)=>{const c=COLORS[i%COLORS.length];s+=`<polyline fill="none" stroke="${c}" stroke-width="2" points="${se.pts.map(p=>sx(p[0])+','+sy(p[1])).join(' ')}"/>`+se.pts.map(p=>`<circle cx="${sx(p[0])}" cy="${sy(p[1])}" r="3" fill="${c}"><title>${se.name}: ${fmt(p[0])}, ${fmt(p[1])}</title></circle>`).join('')});
 s+='</svg>';const d=el('div',{},s);d.appendChild(el('div',{class:'legend'},series.map((se,i)=>`<span><i style="background:${COLORS[i%COLORS.length]}"></i>${se.name}</span>`).join('')));return d}
const banner=(k)=>el('div',{class:'banner '+(k==='syn'?'syn':'thr')},k==='syn'?'<b>Synthetic simulation.</b> Produced by the v2 harness on a synthetic traffic generator. Not testbed measurements. Seeds '+META.seeds.join(', ')+'; Python '+META.python+', NumPy '+META.numpy+', '+META.cores+' core(s).':'<b>Thesis-reported.</b> These values come from the testbed of Chapter 6 and are quoted here; they are not produced by the v2 harness.');
const tabs={};const nav=$('#nav'),main=$('#main');
function add(id,title,build){const b=el('button',{},title),s=el('section',{id});tabs[id]={b,s,build,done:false};b.onclick=()=>show(id);nav.appendChild(b);main.appendChild(s)}
function show(id){for(const k in tabs){tabs[k].b.classList.toggle('on',k===id);tabs[k].s.classList.toggle('on',k===id)}const t=tabs[id];if(!t.done){t.build(t.s);t.done=true}history.replaceState(null,'','#'+id)}
add('overview','Overview',s=>{s.appendChild(el('h2',{},'What this package is'));s.appendChild(el('p',{},'An extended, executable companion to Chapter 6. It adds implementations of each mechanism, deployment files, attack scenarios and cases, an evaluation protocol, and harness results. Harness results and thesis results are kept on separate tabs.'));
 const g=el('div',{class:'grid'});[['Parameters in registry',D.registry.length],['Conflicting statements',D.registry.filter(r=>r.status==='conflict').length],['Scenarios',D.scenarios.length],['Attack cases',D.e10_attack_case_matrix.length/2],['Experiments','E1 to E10'],['Run time (s)',META.total_seconds]].forEach(([a,b])=>g.appendChild(el('div',{class:'card'},`<small>${a}</small><b>${b}</b>`)));s.appendChild(g);
 s.appendChild(el('h2',{},'Reading guide'));s.appendChild(el('p',{},'Blue banner: numbers reported in the thesis. Amber banner: numbers from the synthetic harness. The Consistency tab lists places where Chapter 6 states two different values.'))});
add('thesis','Thesis results',s=>{s.appendChild(banner('thr'));s.appendChild(el('h2',{},'Table 33 with recomputed improvements'));
 const rows=D.thesis33.map(r=>{const low=/FPR|latency/.test(r.metric),hi=/Throughput/.test(r.metric);const f=x=>low?(x/r.a3e).toFixed(2)+'x lower':hi?(r.a3e/x).toFixed(2)+'x higher':'+'+(r.a3e-x).toFixed(2)+' pp';return {...r,'vs DNSGuard':f(r.dnsguard),'vs DeepFingerprint':f(r.deepfingerprint)}});s.appendChild(table(rows));
 s.appendChild(el('h2',{},'Table 32 scenario results'));s.appendChild(table(D.thesis32.map(r=>({...r,'success + fnr':(r.success+r.fnr).toFixed(1)}))))});
add('detect','Detection',s=>{s.appendChild(banner('syn'));s.appendChild(el('h2',{},'F1 by scenario and protocol'));
 const sc=[...new Set(D.e1_per_scenario_protocol.map(r=>r.scenario))],pr=['DoH','DoT','DoQ'];const g=el('div',{class:'heat',style:'grid-template-columns:150px repeat(3,1fr);max-width:560px'});g.appendChild(el('div',{},''));pr.forEach(p=>g.appendChild(el('div',{},'<b>'+p+'</b>')));
 sc.forEach(n=>{g.appendChild(el('div',{style:'text-align:left'},n));pr.forEach(p=>{const r=D.e1_per_scenario_protocol.find(x=>x.scenario===n&&x.protocol===p);const v=r?r.f1:null;g.appendChild(el('div',{style:v===null?'':`background:hsl(${(v-.5)*240},60%,${matchMedia('(prefers-color-scheme:dark)').matches?'30%':'78%'})`},v===null?'':v.toFixed(2)))})});s.appendChild(g);
 s.appendChild(el('h2',{},'Severity sweep'));s.appendChild(lineChart([{name:'F1',pts:D.e1_severity_sweep.map(r=>[r.severity,r.f1])},{name:'recall',pts:D.e1_severity_sweep.map(r=>[r.severity,r.recall])}],{xl:'attack severity',yl:'score'}));
 s.appendChild(el('h2',{},'PGD robustness'));s.appendChild(lineChart(['standard','pgd_trained'].map(m=>({name:m,pts:D.e9_pgd_robustness.filter(r=>r.model===m).map(r=>[r.pgd_eps,r.acc])})),{xl:'PGD epsilon (standardised units)',yl:'accuracy'}));
 s.appendChild(el('h2',{},'Blending evasion'));s.appendChild(lineChart(['standard','pgd_trained'].map(m=>({name:m,pts:D.e9_evasion_blend.filter(r=>r.model===m).map(r=>[r.blend,r.detection_rate])})),{xl:'blend toward tunnel (1 = unmodified)',yl:'detection rate'}));
 s.appendChild(el('h2',{},'Table'));s.appendChild(table(D.e1_per_scenario_protocol))});
add('cases','Attack cases',s=>{s.appendChild(banner('syn'));const row=el('div',{class:'row'});const sel=el('select',{},'<option value="standard">standard detector</option><option value="pgd_trained">PGD-trained detector</option>');row.appendChild(el('span',{},'Model: '));row.appendChild(sel);s.appendChild(row);const box=el('div');s.appendChild(box);
 const V=['baseline','low_and_slow','adaptive_blend'];const draw=()=>{box.innerHTML='';const g=el('div',{class:'heat',style:'grid-template-columns:200px repeat(3,minmax(90px,1fr));max-width:640px'});g.appendChild(el('div',{},''));V.forEach(v=>g.appendChild(el('div',{},'<b>'+v+'</b>')));
  const keys=[...new Set(D.e10_attack_case_matrix.map(r=>r.scenario+' ('+r.protocol+')'))];keys.forEach(k=>{g.appendChild(el('div',{style:'text-align:left'},k));V.forEach(v=>{const r=D.e10_attack_case_matrix.find(x=>x.model===sel.value&&x.scenario+' ('+x.protocol+')'===k&&x.variant===v);g.appendChild(el('div',{style:`background:hsl(${r.recall*120},55%,${matchMedia('(prefers-color-scheme:dark)').matches?'28%':'78%'})`},r.recall.toFixed(2)))})});box.appendChild(g)};sel.onchange=draw;draw();
 s.appendChild(el('h2',{},'Scenario definitions'));const inp=el('input',{placeholder:'filter scenarios'});s.appendChild(inp);const tb=el('div');s.appendChild(tb);const dr=()=>{tb.innerHTML='';const q=inp.value.toLowerCase();tb.appendChild(table(D.scenarios.filter(r=>JSON.stringify(r).toLowerCase().includes(q))))};inp.oninput=dr;dr()});
add('fed','Federated learning',s=>{s.appendChild(banner('syn'));s.appendChild(el('h2',{},'Byzantine sweep'));const row=el('div',{class:'row'});const sel=el('select',{},[...new Set(D.e2_byzantine_sweep.map(r=>r.attack))].map(a=>`<option>${a}</option>`).join(''));row.appendChild(el('span',{},'Attack: '));row.appendChild(sel);s.appendChild(row);const box=el('div');s.appendChild(box);
 const dr=()=>{box.innerHTML='';box.appendChild(lineChart(['mean','median','geomed','mad_geomed'].map(m=>({name:m,pts:D.e2_byzantine_sweep.filter(r=>r.attack===sel.value&&r.method===m).map(r=>[r.byz_frac*100,r.f1])})),{xl:'malicious clients (%)',yl:'F1'}))};sel.onchange=dr;dr();
 s.appendChild(el('h2',{},'Differential privacy sweep (no sub-sampling amplification)'));s.appendChild(table(D.e3_dp_sweep));s.appendChild(el('h2',{},'Noise multiplier required'));s.appendChild(table(D.e3_dp_calibration_grid))});
add('crypto','Cryptography',s=>{s.appendChild(banner('syn'));s.appendChild(el('h2',{},'Noise growth under ciphertext addition (log-log)'));const ps=[...new Set(D.e4_noise_growth.map(r=>r.params))];
 s.appendChild(lineChart(ps.map(p=>({name:p,pts:D.e4_noise_growth.filter(r=>r.params===p&&r.max_abs_noise!==null).map(r=>[r.additions_plus1,r.max_abs_noise])})),{xl:'ciphertexts summed',yl:'max |noise|',logx:true,logy:true}));
 s.appendChild(el('h2',{},'First failing sum'));s.appendChild(table(D.e4_noise_growth.filter(r=>r.max_abs_noise===null).map(r=>({params:r.params,n:r.n,q:r.q,t:r.t,first_failing_sum:r.additions_plus1}))));
 s.appendChild(el('h2',{},'Latency and size'));s.appendChild(table(D.e4_operation_latency));s.appendChild(el('h2',{},'Encrypted histograms'));s.appendChild(table(D.e4_encrypted_histogram));s.appendChild(el('h2',{},'Selective operations'));s.appendChild(table(D.e4_selective_operations))});
add('aee','Adaptive encryption',s=>{s.appendChild(banner('syn'));s.appendChild(el('h2',{},'Diffusion level against KL divergence'));s.appendChild(lineChart([{name:'sigma',pts:D.e5_sigma_vs_kl.map(r=>[r.kl,r.sigma])}],{xl:'KL divergence',yl:'sigma'}));
 s.appendChild(el('h2',{},'Timing adversary against added delay'));s.appendChild(lineChart([{name:'adversary AUC',pts:D.e5_side_channel_tradeoff.map(r=>[r.mean_added_delay_ms,r.adversary_auc])}],{xl:'mean added delay (ms)',yl:'AUC'}));s.appendChild(table(D.e5_side_channel_tradeoff))});
add('ablation','Ablation',s=>{s.appendChild(banner('syn'));s.appendChild(el('p',{},'Components act on separate quantities in the harness, so interactions are zero by construction.'));s.appendChild(table(D.e6_factorial_ablation));
 s.appendChild(el('h2',{},'Sandbox policy rollouts'));s.appendChild(table(D.e7_policy_rollouts));s.appendChild(el('h2',{},'Policy sensitivity'));s.appendChild(table(D.e7_policy_sensitivity));s.appendChild(el('h2',{},'Intelligence fusion'));s.appendChild(table(D.e8_intel_fusion))});
add('audit','Consistency',s=>{s.appendChild(banner('thr'));s.appendChild(el('p',{},'Places where Chapter 6 gives two different values for the same item.'));s.appendChild(table(D.audit,['id','item','s1','s2']));s.appendChild(el('h2',{},'Parameter registry'));const inp=el('input',{placeholder:'filter parameters'});s.appendChild(inp);const tb=el('div');s.appendChild(tb);
 const dr=()=>{tb.innerHTML='';const q=inp.value.toLowerCase();tb.appendChild(table(D.registry.filter(r=>JSON.stringify(r).toLowerCase().includes(q))))};inp.oninput=dr;dr()});
add('figs','Figures',s=>{s.appendChild(banner('syn'));Object.keys(FIGS).forEach(k=>{s.appendChild(el('h2',{},k));s.appendChild(el('img',{src:'data:image/png;base64,'+FIGS[k],alt:k}))})});
show(location.hash.slice(1) in tabs?location.hash.slice(1):'overview');
</script></body></html>"""
out = HTML.replace("__DATA__", json.dumps(data)).replace("__FIGS__", json.dumps(figs)).replace("__META__", json.dumps(meta))
os.makedirs(os.path.join(ROOT, "dashboards"), exist_ok=True)
open(os.path.join(ROOT, "dashboards", "a3e_v2_dashboard.html"), "w", encoding="utf-8").write(out)
print("dashboard", round(len(out) / 1e6, 2), "MB")
