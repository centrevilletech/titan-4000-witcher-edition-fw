import {reduceMotion} from './motion.js';
import {morphHTML} from './morph.js';

// Overview dashboard. The markup is rendered once per visit; live readings,
// meters, charts and the map are then patched in place every second.
export const WINDOWS=[['30s','30 s',30e3],['10m','10 min',600e3],['1h','1 h',3600e3],['6h','6 h',21600e3],['24h','24 h',86400e3]];
const MODULATIONS=['QPSK','16QAM','64QAM','256QAM'];
const DL_TICKS=[0,10,25,50,100,200,350],UL_TICKS=[0,2,5,10,20,35,50];
const SIGNALS={
 rsrp:{label:'RSRP',unit:'dBm',min:-140,max:-60,floor:-115,floorLabel:'Usable −115'},
 sinr:{label:'SINR',unit:'dB',min:-10,max:35,floor:0,floorLabel:'Usable 0'},
 rsrq:{label:'RSRQ',unit:'dB',min:-25,max:-3,floor:-15,floorLabel:'Usable −15'}
};
const ZOOM_MIN=3,ZOOM_MAX=18;
const finite=value=>typeof value==='number'&&Number.isFinite(value);
const mbps=bps=>finite(bps)?bps/1e6:null;
const fmt=(value,digits=1)=>finite(value)?value.toFixed(digits):'—';
const rate=value=>!finite(value)?'—':value===0?'0':value>=100?value.toFixed(0):value>=10?value.toFixed(1):value.toFixed(2);
const clamp=(value,min,max)=>Math.max(min,Math.min(max,value));
// An idle direction still reports a scheme (QPSK at MCS 0, or a stale MCS),
// and the modem's own rate is noisy. Trust the interface counters instead.
const moving=(info,bps)=>!!info?.modulation&&finite(info.mcs)&&info.mcs>0&&(finite(bps)?bps>=20000:!finite(info.modem_bps)||info.modem_bps>=20000);
const average=list=>{const values=list.filter(finite);return values.length?values.reduce((a,b)=>a+b,0)/values.length:null;};

export function linkQuality(sinr,rsrp){
 if(!finite(sinr))return ['Waiting for signal','muted'];
 if(sinr>=20&&(!finite(rsrp)||rsrp>=-100))return ['Excellent link','good'];
 if(sinr>=13)return ['Good link','good'];
 if(sinr>=5)return ['Fair link','fair'];
 return ['Weak link','weak'];
}
// Speedometer scale: evenly spaced ticks with linear steps between, so a few
// Mbps still moves the needle on a 350 Mbps dial.
function scaleFraction(value,ticks){
 if(!finite(value)||value<=0)return 0;
 const last=ticks.length-1;if(value>=ticks[last])return 1;
 const i=ticks.findIndex(t=>t>value)-1;
 return (i+(value-ticks[i])/(ticks[i+1]-ticks[i]))/last;
}
const SWEEP=240,START=-120;
function polar(cx,cy,r,deg){const a=(deg-90)*Math.PI/180;return [cx+r*Math.cos(a),cy+r*Math.sin(a)];}
function arc(cx,cy,r,from,to){const [x1,y1]=polar(cx,cy,r,from),[x2,y2]=polar(cx,cy,r,to);return `M${x1.toFixed(2)} ${y1.toFixed(2)}A${r} ${r} 0 ${to-from>180?1:0} 1 ${x2.toFixed(2)} ${y2.toFixed(2)}`;}

// Dial geometry (SVG units). Tick labels sit outside the arc and the readout
// sits below it, so the needle never crosses text.
const DIAL={c:130,r:100,width:260,height:192};
function speedometer(id,label,ticks,icon){
 const {c,r}=DIAL,full=arc(c,c,r,START,START+SWEEP);
 const marks=ticks.map((t,i)=>{
  const deg=START+SWEEP*i/(ticks.length-1),[x1,y1]=polar(c,c,r-9,deg),[x2,y2]=polar(c,c,r-15,deg),[lx,ly]=polar(c,c,r+15,deg);
  return `<line class="speedo-tick" x1="${x1.toFixed(1)}" y1="${y1.toFixed(1)}" x2="${x2.toFixed(1)}" y2="${y2.toFixed(1)}"/><text x="${lx.toFixed(1)}" y="${(ly+3.5).toFixed(1)}">${t}</text>`;
 }).join('');
 const minor=ticks.slice(0,-1).map((_,i)=>{const deg=START+SWEEP*(i+.5)/(ticks.length-1),[x1,y1]=polar(c,c,r-9,deg),[x2,y2]=polar(c,c,r-12,deg);return `<line class="speedo-minor" x1="${x1.toFixed(1)}" y1="${y1.toFixed(1)}" x2="${x2.toFixed(1)}" y2="${y2.toFixed(1)}"/>`;}).join('');
 return `<div class="speedo" data-speedo="${id}">
  <span class="speedo-label">${icon}${label}</span>
  <svg viewBox="0 0 ${DIAL.width} ${DIAL.height}" aria-hidden="true">
   <path class="speedo-track" d="${full}"/>
   <path class="speedo-peak" data-speedo-peak d="${full}" pathLength="1000" stroke-dasharray="0 1000"/>
   <path class="speedo-value" data-speedo-value d="${full}" pathLength="1000" stroke-dasharray="0 1000"/>
   ${minor}${marks}
   <g class="speedo-peak-mark" data-speedo-peak-mark style="transform:rotate(${START}deg)"><path d="M${c-4} ${c-r-9} L${c+4} ${c-r-9} L${c} ${c-r-2} Z"/></g>
   <g class="speedo-needle" data-speedo-needle style="transform:rotate(${START}deg)"><path d="M${c-2.2} ${c} L${c-.6} ${c-r+22} L${c+.6} ${c-r+22} L${c+2.2} ${c} Z"/><circle cx="${c}" cy="${c}" r="7"/><circle class="speedo-hub" cx="${c}" cy="${c}" r="2.5"/></g>
  </svg>
  <div class="speedo-readout"><strong><span data-speedo-text>—</span><small>Mbps</small></strong><span class="speedo-foot" data-speedo-foot><span>Peak <b data-speedo-peak-text>—</b></span><span>Avg <b data-speedo-avg-text>—</b></span></span></div>
 </div>`;
}
function scale(id,items,label){
 return `<div class="scale" data-scale="${id}" role="img" aria-label="${label}"><div class="scale-track">${items.map(item=>`<span data-scale-item="${item}">${item}</span>`).join('')}<i class="scale-thumb" data-scale-thumb></i></div></div>`;
}
function signalBar(key){
 const s=SIGNALS[key],floor=(s.floor-s.min)/(s.max-s.min)*100;
 return `<div class="signal-row" data-signal="${key}"><div class="signal-head"><span>${s.label}</span><strong><span data-live="${key}">—</span><small>${s.unit}</small></strong><span class="signal-avg" data-signal-avg>Avg —</span></div>
  <div class="signal-bar"><i class="signal-fill" data-signal-fill></i><i class="signal-floor" style="left:${floor.toFixed(1)}%" title="${s.floorLabel} ${s.unit}"></i><i class="signal-mark" data-signal-mark hidden></i></div>
  <div class="signal-scale"><span>${s.min}</span><span>${s.max}</span></div></div>`;
}

export function renderDashboard({esc,icon,config,head,subtitle,defaults={}}){
 const d=key=>esc(defaults[key]??'—');
 return `${head('','Overview',subtitle)}
 <section class="card dash-link" aria-label="Connection">
  <div class="dash-link-title"><h2 data-link-quality>Waiting for signal</h2><span data-status></span></div>
  <div class="dash-path">
   <div class="dash-node">${icon('RadioTower')}<div><strong>LTE cell</strong><span>PCI <span data-live="pci">—</span> · Band <span data-device="band">${d('band')}</span></span><span class="code">EARFCN <span data-device="earfcn">${d('earfcn')}</span></span></div></div>
   <div class="dash-wire dash-wire-radio" data-wire="radio"><span class="dash-wire-label" data-carrier-summary>—</span><i class="dash-wire-line"><b></b><b></b><b></b></i><span class="dash-wire-sub" data-modulation-summary>—</span></div>
   <div class="dash-node dash-node-device">${icon('Monitor')}<div><strong>Titan 4000</strong><span>${esc(config.mode).replace('IP ','')}</span><span data-device="serial">${d('serial')}</span></div></div>
   <div class="dash-wire" data-ethernet-link><span class="dash-wire-label" data-ethernet-speed>—</span><i class="dash-wire-line"></i><span class="dash-wire-sub">Ethernet</span></div>
   <div class="dash-node">${icon('Network')}<div><strong>Router</strong><span class="code" data-device="customer">${d('customer')}</span><span>Customer IPv4</span></div></div>
  </div>
  <div class="dash-path-meta" aria-hidden="true"><span><em>Radio</em><b data-path-meta="radio">—</b></span><span><em>Ethernet</em><b data-path-meta="ethernet">—</b></span></div>
  <div class="ethernet-notice" data-ethernet-notice hidden role="status"></div>
 </section>
 <div class="dash-grid">
  <section class="card card-pad dash-speed"><div class="card-head"><h2>Throughput</h2><span class="muted text-xs" data-speed-window>Last 30 s</span></div><div class="speedo-pair">${speedometer('dl','Download',DL_TICKS,icon('ArrowDown'))}${speedometer('ul','Upload',UL_TICKS,icon('ArrowUp'))}</div></section>
  <section class="card card-pad dash-signal"><div class="card-head"><h2>Signal</h2><span class="muted text-xs" data-radio-age>—</span></div>${signalBar('rsrp')}${signalBar('sinr')}${signalBar('rsrq')}<div class="signal-key"><span><i class="signal-key-floor"></i>Minimum usable (RSRP −115, SINR 0, RSRQ −15)</span><span><i class="signal-key-avg"></i>Average for the selected range</span></div><div class="signal-extra"><span>CQI <strong data-dash="cqi">—</strong></span><span>MIMO rank <strong data-dash="ri">—</strong></span><span>RX chains <strong data-live="chains">—</strong></span></div></section>
  <section class="card card-pad dash-carriers"><div class="card-head"><h2>Carrier aggregation</h2><span class="muted text-xs" data-carrier-bandwidth>—</span></div>${scale('carriers',['1 CC','2 CC','3 CC','4 CC'],'Aggregated component carriers')}<div class="ca-legend"><span><i class="ca-key ca-key-busy"></i>Carrying traffic</span><span><i class="ca-key ca-key-ready"></i>Aggregated, on standby</span></div><p class="scale-caption" data-carrier-caption>—</p><div class="carrier-list" data-carrier-list></div></section>
  <section class="card card-pad dash-modulation"><div class="card-head"><h2>Modulation</h2><span class="muted text-xs">Current scheme</span></div>
   <div class="mod-row"><div class="mod-head"><span>Downlink</span><strong data-mod-text="dl">—</strong></div>${scale('dl-mod',MODULATIONS,'Downlink modulation')}</div>
   <div class="mod-row"><div class="mod-head"><span>Uplink</span><strong data-mod-text="ul">—</strong></div>${scale('ul-mod',MODULATIONS,'Uplink modulation')}</div>
   <div class="mod-share" data-mod-share></div>
  </section>
 </div>
 <section class="card card-pad dash-history">
  <div class="card-head dash-history-head"><div><h2>History</h2><p class="muted text-xs mt-1" data-history-note>Live</p></div><div class="range" role="tablist" aria-label="History range">${WINDOWS.map(([id,label])=>`<button type="button" role="tab" data-range="${id}" aria-selected="false">${label}</button>`).join('')}<i class="range-thumb" data-range-thumb></i></div></div>
  <div class="dash-stats" data-history-stats></div>
  <div class="history-charts">
   <figure class="history-chart" data-chart-box="throughput"><figcaption><span>Throughput <em>Mbps</em></span><span class="legend-dl">Download</span><span class="legend-ul">Upload</span></figcaption><svg data-history="throughput" role="img" aria-label="Throughput history"></svg><div class="history-tip" data-tip hidden></div></figure>
   <figure class="history-chart" data-chart-box="signal"><figcaption><span>Signal</span><span class="legend-sinr">SINR dB</span><span class="legend-rsrp">RSRP dBm</span></figcaption><svg data-history="signal" role="img" aria-label="Signal history"></svg><div class="history-tip" data-tip hidden></div></figure>
  </div>
 </section>
 <div class="dash-grid dash-grid-bottom">
  <section class="card dash-map"><div class="card-head card-pad-x"><h2>Location</h2><span class="muted text-xs" data-gps-status>Waiting for GPS</span></div><div class="map" data-map><div class="map-tiles" data-map-tiles></div><div class="map-marker" data-map-marker hidden><i></i><i></i><b></b></div><div class="map-wait" data-map-wait><span class="map-radar"></span><strong>Waiting for a GPS fix</strong><small>The Titan reports its position once the receiver locks.</small></div><div class="map-zoom"><button type="button" class="icon-button" data-map-zoom="1" aria-label="Zoom in">${icon('Plus')}</button><button type="button" class="icon-button" data-map-zoom="-1" aria-label="Zoom out">${icon('Minus')}</button></div><span class="map-credit">© OpenStreetMap contributors</span></div><dl class="map-facts"><div><dt>Latitude</dt><dd class="code" data-gps="latitude">—</dd></div><div><dt>Longitude</dt><dd class="code" data-gps="longitude">—</dd></div><div><dt>Altitude</dt><dd class="code" data-gps="altitude">—</dd></div><div><dt>Map</dt><dd><a data-gps="link" target="_blank" rel="noopener" hidden>Open in maps ↗</a><span data-gps="nolink">—</span></dd></div></dl></section>
  <section class="card card-pad dash-health"><div class="card-head"><h2>Connection health</h2>${icon('ShieldCheck')}</div>
   ${[['Radio link','Serving cell attachment','RadioTower','radio'],['Spectrum access','SAS registration and grant','ShieldCheck','sas'],['Customer data','Customer bearer address','Globe','data'],['Ethernet','Downstream router','Cable','ethernet']].map(([title,sub,ic,key])=>`<div class="health-row">${icon(ic)}<div><strong>${title}</strong><small>${sub}</small></div><span data-health="${key}">—</span></div>`).join('')}
   <dl class="definition"><div><dt>Network</dt><dd data-device="network">${d('network')}</dd></div><div><dt>Management IP</dt><dd class="code" data-device="management">${d('management')}</dd></div></dl>
  </section>
 </div>`;
}

// Charts: time-based x axis so the live window scrolls smoothly between samples.
// Axis steps of 1, 2, 2.5 or 5 × 10ⁿ, about four per axis.
function niceStep(raw){const p=10**Math.floor(Math.log10(raw)),n=raw/p;return ([1,2,2.5,5,10].find(step=>n<=step)??10)*p;}
function niceScale(max,count=4){const step=niceStep(Math.max(max,1e-9)/count);return {step,top:Math.max(step,Math.ceil(max/step)*step)};}
const TIME_STEPS={'30s':10e3,'10m':120e3,'1h':900e3,'6h':3600e3,'24h':4*3600e3};
const CHART_H=196,GUTTER={top:12,bottom:26,left:46};
function path(points,x,y,key){
 let d='',open=false;
 for(const p of points){const v=p[key];if(!finite(v)){open=false;continue;}d+=`${open?'L':'M'}${x(p.t).toFixed(1)} ${y(v).toFixed(1)}`;open=true;}
 return d;
}
function area(points,x,y,key,base){
 const runs=[];let run=[];
 for(const p of points){if(finite(p[key]))run.push(p);else if(run.length){runs.push(run);run=[];}}
 if(run.length)runs.push(run);
 return runs.map(r=>`M${x(r[0].t).toFixed(1)} ${base}`+r.map(p=>`L${x(p.t).toFixed(1)} ${y(p[key]).toFixed(1)}`).join('')+`L${x(r.at(-1).t).toFixed(1)} ${base}Z`).join('');
}
function timeLabel(ms,window){const d=new Date(ms);return window==='30s'?d.toLocaleTimeString([], {hour:'numeric',minute:'2-digit',second:'2-digit'}):d.toLocaleTimeString([], {hour:'numeric',minute:'2-digit'});}

export class Dashboard {
 constructor(){this.root=null;this.source=null;this.window='30s';this.live=[];this.history=null;this.request=0;this.frame=0;this.timer=0;this.zoom=15;this.tiles='';this.lastSample=0;this.hover={};}
 mount(root,source){
  this.unmount();this.root=root;this.source=source;
  this.window=sessionStorage.getItem('titan-history-window')||'30s';if(!WINDOWS.some(w=>w[0]===this.window))this.window='30s';
  root.addEventListener('click',this.onClick=event=>this.click(event));
  root.addEventListener('pointermove',this.onMove=event=>this.move(event));
  root.addEventListener('pointerleave',this.onLeave=()=>this.leave(),true);
  root.addEventListener('load',this.onLoad=event=>{if(event.target.matches?.('.map-tiles img'))event.target.classList.add('loaded');},true);
  this.resize?.disconnect();
  if('ResizeObserver' in window){this.resize=new ResizeObserver(()=>{this.selectRange(false);if(this.window!=='30s')this.draw(Date.now());this.paintMap(this.snapshot?.gps);});for(const el of root.querySelectorAll('[data-history],[data-map],.range'))this.resize.observe(el);}
  this.selectRange(false);this.load();this.update();this.loop();
 }
 unmount(){cancelAnimationFrame(this.frame);clearTimeout(this.timer);if(this.root){this.root.removeEventListener('click',this.onClick);this.root.removeEventListener('pointermove',this.onMove);this.root.removeEventListener('pointerleave',this.onLeave,true);this.root.removeEventListener('load',this.onLoad,true);}clearInterval(this.timer2);this.resize?.disconnect();this.root=null;this.request++;this.tiles='';}
 get mounted(){return !!this.root?.isConnected;}
 $(selector){return this.root?.querySelector(selector);}
 $$(selector){return [...(this.root?.querySelectorAll(selector)||[])];}
 click(event){
  const range=event.target.closest('[data-range]');
  if(range&&range.dataset.range!==this.window){this.window=range.dataset.range;try{sessionStorage.setItem('titan-history-window',this.window);}catch{}this.history=null;this.selectRange(true);this.load();this.paintHistory();return;}
  const zoom=event.target.closest('[data-map-zoom]');
  if(zoom){this.zoom=clamp(this.zoom+Number(zoom.dataset.mapZoom),ZOOM_MIN,ZOOM_MAX);this.tiles='';this.paintMap(this.snapshot?.gps);}
 }
 selectRange(animate){
  const list=this.$('.range'),thumb=this.$('[data-range-thumb]');if(!list)return;
  for(const button of list.querySelectorAll('[data-range]')){const active=button.dataset.range===this.window;button.classList.toggle('active',active);button.setAttribute('aria-selected',String(active));if(active&&thumb){thumb.style.transition=animate?'':'none';thumb.style.width=button.offsetWidth+'px';thumb.style.transform=`translateX(${button.offsetLeft}px)`;}}
  const label=WINDOWS.find(w=>w[0]===this.window)[1];
  const speed=this.$('[data-speed-window]');if(speed)speed.textContent=`Last ${label}`;
 }
 async load(){
  const serial=++this.request,window=this.window;clearTimeout(this.timer);
  try{
   const data=await this.source.history(window);
   if(serial!==this.request||!this.mounted)return;
   this.history=data;
   if(window==='30s'){const known=new Set(this.live.map(p=>p.t));for(const p of data?.points||[])if(!known.has(p.t))this.live.push(p);this.live.sort((a,b)=>a.t-b.t);this.trim();}
  }catch{if(serial!==this.request)return;this.history=this.history||{points:[],summary:null,error:true};}
  this.paintHistory();
  const refresh={'30s':0,'10m':10e3,'1h':30e3,'6h':60e3,'24h':120e3}[window];
  if(refresh)this.timer=setTimeout(()=>{if(this.mounted&&this.window===window)this.load();},refresh);
 }
 trim(){const cutoff=Date.now()-36e3;this.live=this.live.filter(p=>p.t>=cutoff);}
 // Called every second with the latest normalized reading.
 update(){
  if(!this.mounted)return;
  const s=this.source.live();this.snapshot=s;
  if(s?.sampledAt&&s.sampledAt!==this.lastSample){
   this.lastSample=s.sampledAt;
   this.live.push({t:s.sampledAt,dl:s.fresh?s.dl_bps:null,ul:s.fresh?s.ul_bps:null,dl_max:s.fresh?s.dl_bps:null,ul_max:s.fresh?s.ul_bps:null,rsrp:s.fresh?s.rsrp:null,sinr:s.fresh?s.sinr:null,rsrq:s.fresh?s.rsrq:null,cqi:s.fresh?s.cqi:null,carriers:s.fresh?s.active:null,dl_mod:s.fresh&&moving(s.dl,s.dl_bps)?s.dl.modulation:null});
   this.trim();
  }
  this.paintLive(s);
  if(this.window==='30s')this.paintStats();
 }
 summary(){
  if(this.window!=='30s')return this.history?.summary||null;
  const pts=this.live.filter(p=>p.t>=Date.now()-30e3);if(!pts.length)return null;
  const values=key=>pts.map(p=>p[key]).filter(finite);
  const share=(key,labels)=>{const list=pts.map(p=>p[key]).filter(v=>v!==null&&v!==undefined);if(!list.length)return null;return Object.fromEntries(labels.map(l=>[l,list.filter(v=>String(key==='carriers'?Math.round(v):v)===l).length/list.length]));};
  return {dl_avg:average(values('dl')),dl_peak:values('dl').length?Math.max(...values('dl')):null,ul_avg:average(values('ul')),ul_peak:values('ul').length?Math.max(...values('ul')):null,rsrp_avg:average(values('rsrp')),rsrp_min:values('rsrp').length?Math.min(...values('rsrp')):null,rsrp_max:values('rsrp').length?Math.max(...values('rsrp')):null,sinr_avg:average(values('sinr')),sinr_min:values('sinr').length?Math.min(...values('sinr')):null,sinr_max:values('sinr').length?Math.max(...values('sinr')):null,rsrq_avg:average(values('rsrq')),cqi_avg:average(values('cqi')),carriers:share('carriers',['1','2','3','4']),dl_modulation:share('dl_mod',MODULATIONS),coverage:Math.min(1,pts.length/30)};
 }
 paintLive(s){
  const fresh=!!s?.fresh;
  const [quality,tone]=fresh?linkQuality(s.sinr,s.rsrp):[s?.attached===false?'Not attached':'Waiting for signal','muted'];
  const title=this.$('[data-link-quality]');if(title){if(title.textContent!==quality)title.textContent=quality;title.dataset.tone=tone;}
  // Data-flow dots run faster with more traffic and stop when idle.
  const wire=this.$('[data-wire=radio]');
  if(wire){const total=(mbps(s?.dl_bps)||0)+(mbps(s?.ul_bps)||0);wire.dataset.flow=!fresh?'off':total>50?'fast':total>5?'medium':total>0.2?'slow':'idle';}
  this.$$('[data-carrier-summary]').forEach(el=>morphHTML(el,fresh&&s.configured?`<span class="long">${s.configured} carrier${s.configured===1?'':'s'}</span><span class="short">${s.configured} CC</span>${s.bandwidth?` · ${s.bandwidth} MHz`:''}`:'—'));
  const scheme=(info,bps)=>!info?.modulation?'—':moving(info,bps)?info.modulation:'idle';
  this.$$('[data-modulation-summary]').forEach(el=>{const text=fresh&&s.dl?.modulation?`DL ${scheme(s.dl,s.dl_bps)} · UL ${scheme(s.ul,s.ul_bps)}`:'—';if(el.textContent!==text)el.textContent=text;});
  // Phones show the wire labels as one summary row under the path.
  const meta=(key,text)=>{const el=this.$(`[data-path-meta=${key}]`);if(el&&el.textContent!==text)el.textContent=text;};
  meta('radio',fresh&&s.configured?`${s.configured} CC${s.bandwidth?` · ${s.bandwidth} MHz`:''} · DL ${scheme(s.dl,s.dl_bps)}`:'—');
  meta('ethernet',this.$('[data-ethernet-speed]')?.textContent||'—');
  const sum=this.summary();
  this.speed('dl',fresh?mbps(s.dl_bps):null,mbps(sum?.dl_peak),mbps(sum?.dl_avg),DL_TICKS);
  this.speed('ul',fresh?mbps(s.ul_bps):null,mbps(sum?.ul_peak),mbps(sum?.ul_avg),UL_TICKS);
  for(const key of Object.keys(SIGNALS))this.signal(key,fresh?s[key]:null,sum?.[`${key}_avg`]);
  const set=(selector,value)=>this.$$(selector).forEach(el=>{if(el.textContent!==String(value))el.textContent=value;});
  set('[data-dash=cqi]',fresh&&finite(s.cqi)?s.cqi:'—');set('[data-dash=ri]',fresh&&finite(s.ri)?s.ri:'—');
  set('[data-radio-age]',!s?'—':!fresh?'No fresh readings':finite(s.radioAge)?(s.radioAge<1500?'Radio updated just now':`Radio updated ${Math.round(s.radioAge/1000)} s ago`):'Live');
  this.carriers(s,fresh);
  this.modulation('dl',fresh?s.dl:null,s?.dl_bps);this.modulation('ul',fresh?s.ul:null,s?.ul_bps);
  this.paintMap(s?.gps);
 }
 speed(id,value,peak,avg,ticks){
  const box=this.$(`[data-speedo=${id}]`);if(!box)return;
  // Every moving part is a rotation or a dash length on a fixed path, so the
  // browser interpolates it cleanly in both directions.
  const fraction=scaleFraction(value??0,ticks),peakFraction=Math.max(fraction,scaleFraction(peak??0,ticks));
  box.querySelector('[data-speedo-needle]').style.transform=`rotate(${(START+SWEEP*fraction).toFixed(2)}deg)`;
  box.querySelector('[data-speedo-value]').style.strokeDasharray=`${(fraction*1000).toFixed(1)} 1000`;
  box.querySelector('[data-speedo-peak]').style.strokeDasharray=`${(peakFraction*1000).toFixed(1)} 1000`;
  const mark=box.querySelector('[data-speedo-peak-mark]');mark.style.transform=`rotate(${(START+SWEEP*peakFraction).toFixed(2)}deg)`;mark.classList.toggle('visible',finite(peak)&&peak>0);
  box.classList.toggle('speedo-idle',value===null);
  this.tween(box.querySelector('[data-speedo-text]'),value);
  const set=(selector,text)=>{const el=box.querySelector(selector);if(el.textContent!==text)el.textContent=text;};
  set('[data-speedo-peak-text]',rate(peak));set('[data-speedo-avg-text]',rate(avg));
 }
 // Count the readout toward its new value instead of jumping.
 tween(element,target){
  if(!element)return;
  if(!finite(target)){element.dataset.value='';element.textContent='—';return;}
  const from=Number(element.dataset.value);element.dataset.value=String(target);
  if(!finite(from)||reduceMotion()){element.textContent=rate(target);return;}
  const start=performance.now(),duration=800;
  const step=now=>{if(element.dataset.value!==String(target))return;const k=Math.min(1,(now-start)/duration),e=1-(1-k)**3;element.textContent=rate(from+(target-from)*e);if(k<1)requestAnimationFrame(step);};
  requestAnimationFrame(step);
 }
 signal(key,value,avg){
  const row=this.$(`[data-signal=${key}]`);if(!row)return;const s=SIGNALS[key],pct=v=>clamp((v-s.min)/(s.max-s.min)*100,0,100);
  row.querySelector('[data-signal-fill]').style.width=`${finite(value)?pct(value):0}%`;
  row.dataset.tone=!finite(value)?'muted':value<s.floor?'weak':value<s.floor+(s.max-s.floor)*.35?'fair':'good';
  const mark=row.querySelector('[data-signal-mark]');mark.hidden=!finite(avg);if(finite(avg))mark.style.left=`${pct(avg)}%`;
  const text=`Avg ${fmt(avg)}`,el=row.querySelector('[data-signal-avg]');if(el.textContent!==text)el.textContent=text;
 }
 // Segmented scale: a solid thumb for the current value and, for carriers, a
 // lighter band for everything aggregated behind it.
 thumb(id,index,count,extent){
  const box=this.$(`[data-scale="${id}"]`);if(!box)return;
  const thumb=box.querySelector('[data-scale-thumb]'),items=[...box.querySelectorAll('[data-scale-item]')];
  let band=box.querySelector('[data-scale-band]');
  if(extent!==undefined&&!band){band=document.createElement('i');band.className='scale-band';band.dataset.scaleBand='';thumb.before(band);}
  items.forEach((item,i)=>{item.classList.toggle('active',i<=index&&(extent!==undefined||i===index));item.classList.toggle('ready',extent!==undefined&&i>index&&i<extent);});
  box.classList.toggle('scale-empty',index<0);
  if(extent!==undefined){thumb.style.left='0';thumb.style.width=`${Math.max(0,index+1)/count*100}%`;band.style.width=`${clamp(extent,0,count)/count*100}%`;return;}
  if(index>=0){thumb.style.left=`${index/count*100}%`;thumb.style.width=`${100/count}%`;}
 }
 // The network aggregates carriers ahead of demand; secondaries only carry
 // traffic (report a real MCS) while there is enough load to schedule them.
 carriers(s,fresh){
  const list=fresh?s.carriers||[]:[],configured=fresh?s.configured||list.length:0;
  const busy=c=>c.role==='pcc'?moving(s?.dl,s?.dl_bps):c.active&&finite(c.dl_mcs)&&c.dl_mcs>0&&finite(s?.dl_bps)&&s.dl_bps>=20000;
  const carrying=list.filter(busy).length;
  this.thumb('carriers',carrying-1,4,configured);
  const caption=this.$('[data-carrier-caption]');
  if(caption){const text=!fresh?'Waiting for radio readings':configured<=1?(carrying?'Single carrier carrying traffic':'Single carrier · idle'):carrying>1?`${carrying} of ${configured} carriers carrying traffic`:`${configured} carriers aggregated · secondaries engage under load`;if(caption.textContent!==text)caption.textContent=text;}
  const bw=this.$('[data-carrier-bandwidth]');if(bw){const text=fresh&&s.bandwidth?`${s.bandwidth} MHz aggregated`:'—';if(bw.textContent!==text)bw.textContent=text;}
  const box=this.$('[data-carrier-list]');if(!box)return;
  const rows=list.map(c=>{const on=busy(c);return `<div class="carrier ${on?'is-busy':''}"><span class="carrier-role">${c.role==='pcc'?'Primary':'Secondary '+c.index}</span><span class="carrier-cell">B${c.band??'—'} · ${finite(c.bandwidth_mhz)?Math.round(c.bandwidth_mhz):'—'} MHz<small>EARFCN ${c.earfcn??'—'} · PCI ${c.pci??'—'}</small></span><span class="carrier-sig">${fmt(c.rsrp,0)} dBm<small>SINR ${fmt(c.sinr,0)} dB</small></span><span class="carrier-state">${on?`<b>${c.role==='pcc'?s.dl.modulation:(c.dl_modulation||'—')}</b>`:c.role==='pcc'?'Idle':'Standby'}</span></div>`;}).join('');
  morphHTML(box,rows||'<p class="muted text-xs">No carrier details yet.</p>');
 }
 modulation(id,info,bps){
  const idle=!!info?.modulation&&!moving(info,bps),index=info?.modulation&&!idle?MODULATIONS.indexOf(info.modulation):-1;
  this.thumb(`${id}-mod`,index,MODULATIONS.length);
  const text=idle?'Idle':info?.modulation?`${info.modulation}${finite(info.mcs)?` · MCS ${info.mcs}`:''}`:'—',el=this.$(`[data-mod-text=${id}]`);if(el&&el.textContent!==text)el.textContent=text;
 }
 paintStats(){
  const box=this.$('[data-history-stats]');if(!box)return;const s=this.summary();
  const tile=(label,value,unit)=>`<div class="dash-stat"><span>${label}</span><strong>${value}<small>${unit}</small></strong></div>`;
  const share=s?.dl_modulation?MODULATIONS.map(m=>[m,s.dl_modulation[m]||0]).filter(([,v])=>v>0):[];
  morphHTML(box,`${tile('Avg download',rate(mbps(s?.dl_avg)),'Mbps')}${tile('Peak download',rate(mbps(s?.dl_peak)),'Mbps')}${tile('Avg upload',rate(mbps(s?.ul_avg)),'Mbps')}${tile('Avg SINR',fmt(s?.sinr_avg),'dB')}${tile('Avg RSRP',fmt(s?.rsrp_avg),'dBm')}${tile('Avg RSRQ',fmt(s?.rsrq_avg),'dB')}`);
  const mod=this.$('[data-mod-share]');
  if(mod)morphHTML(mod,share.length?`<span class="mod-share-label">Downlink time at each scheme</span><div class="mod-share-bar">${share.map(([m,v])=>`<i class="mod-${m.toLowerCase()}" style="flex:${v.toFixed(3)}" title="${m} ${(v*100).toFixed(0)}%"></i>`).join('')}</div><div class="mod-share-key">${share.map(([m,v])=>`<span><i class="mod-${m.toLowerCase()}"></i>${m} ${(v*100).toFixed(0)}%</span>`).join('')}</div>`:'');
 }
 points(){
  if(this.window==='30s')return this.live;
  return this.history?.points||[];
 }
 paintHistory(){
  if(!this.mounted)return;
  this.paintStats();
  const note=this.$('[data-history-note]'),span=WINDOWS.find(w=>w[0]===this.window)[2];
  if(note){const h=this.history,text=this.window==='30s'?'Live · updates every second':!h?'Loading from the Titan…':h.error?'History unavailable':h.oldest_unix_ms&&Date.now()-h.oldest_unix_ms<span*.98?`Recorded since ${new Date(h.oldest_unix_ms).toLocaleString([], {hour:'2-digit',minute:'2-digit',month:'short',day:'numeric'})}`:'Stored on the Titan';if(note.textContent!==text)note.textContent=text;}
  this.$$('[data-chart-box]').forEach(box=>box.classList.toggle('loading',this.window!=='30s'&&!this.history));
  if(this.window!=='30s')this.draw(Date.now());
 }
 loop(){
  cancelAnimationFrame(this.frame);
  const tick=()=>{if(!this.mounted)return;if(this.window==='30s'&&!document.hidden)this.draw(Date.now()-1000);this.frame=requestAnimationFrame(tick);};
  if(reduceMotion()){this.timer2=setInterval(()=>{if(!this.mounted){clearInterval(this.timer2);return;}if(this.window==='30s')this.draw(Date.now()-1000);},1000);return;}
  this.frame=requestAnimationFrame(tick);
 }
 // Charts are drawn at their real pixel size so text and strokes never stretch.
 size(svg){const width=Math.max(240,Math.round(svg.clientWidth||600));if(svg.dataset.width!==String(width)){svg.dataset.width=width;svg.setAttribute('viewBox',`0 0 ${width} ${CHART_H}`);}return width;}
 chartBox(svg,right){
  const width=this.size(svg),span=WINDOWS.find(w=>w[0]===this.window)[2];
  return {width,span,left:GUTTER.left,right:width-right,top:GUTTER.top,bottom:CHART_H-GUTTER.bottom};
 }
 draw(now){
  const span=WINDOWS.find(w=>w[0]===this.window)[2],start=now-span,points=this.points().filter(p=>p.t>=start-span*.05&&p.t<=now+5e3);
  const throughput=this.$('[data-history=throughput]');
  if(throughput){
   const f=this.chartBox(throughput,12),x=t=>f.left+(t-start)/span*(f.right-f.left);
   const peak=Math.max(1e6,...points.map(p=>Math.max(p.dl_max??p.dl??0,p.ul_max??p.ul??0)));
   const {step,top}=niceScale(peak/1e6),y=v=>f.bottom-(v/1e6/top)*(f.bottom-f.top);
   let grid='';for(let v=0;v<=top+1e-9;v+=step)grid+=`<line class="grid" x1="${f.left}" x2="${f.right}" y1="${y(v*1e6).toFixed(1)}" y2="${y(v*1e6).toFixed(1)}"/><text class="axis" x="${f.left-8}" y="${(y(v*1e6)+3.5).toFixed(1)}" text-anchor="end">${+v.toFixed(2)}</text>`;
   throughput.innerHTML=`<defs><linearGradient id="fill-dl" x1="0" y1="0" x2="0" y2="1"><stop offset="0" class="stop-dl" stop-opacity=".28"/><stop offset="1" class="stop-dl" stop-opacity="0"/></linearGradient><linearGradient id="fill-ul" x1="0" y1="0" x2="0" y2="1"><stop offset="0" class="stop-ul" stop-opacity=".24"/><stop offset="1" class="stop-ul" stop-opacity="0"/></linearGradient><clipPath id="clip-throughput"><rect x="${f.left}" y="0" width="${f.right-f.left}" height="${CHART_H}"/></clipPath></defs>${grid}<g clip-path="url(#clip-throughput)"><path class="area-dl" d="${area(points,x,y,'dl',f.bottom)}"/><path class="area-ul" d="${area(points,x,y,'ul',f.bottom)}"/><path class="line-ul" d="${path(points,x,y,'ul')}"/><path class="line-dl" d="${path(points,x,y,'dl')}"/></g>${this.axis(start,span,f)}${this.cursor('throughput',points,x,y,['dl','ul'],f)}`;
  }
  const signal=this.$('[data-history=signal]');
  if(signal){
   const f=this.chartBox(signal,46),x=t=>f.left+(t-start)/span*(f.right-f.left);
   // SINR −10…30 dB pairs with RSRP −140…−60 dBm so both axes land on round numbers.
   const ys=v=>f.bottom-(clamp(v,-10,30)+10)/40*(f.bottom-f.top),yr=v=>f.bottom-(clamp(v,-140,-60)+140)/80*(f.bottom-f.top);
   const grid=[-10,0,10,20,30].map(v=>`<line class="grid" x1="${f.left}" x2="${f.right}" y1="${ys(v).toFixed(1)}" y2="${ys(v).toFixed(1)}"/><text class="axis axis-sinr" x="${f.left-8}" y="${(ys(v)+3.5).toFixed(1)}" text-anchor="end">${v}</text><text class="axis axis-rsrp" x="${f.right+8}" y="${(ys(v)+3.5).toFixed(1)}">${-140+(v+10)*2}</text>`).join('');
   signal.innerHTML=`<defs><clipPath id="clip-signal"><rect x="${f.left}" y="0" width="${f.right-f.left}" height="${CHART_H}"/></clipPath></defs>${grid}<g clip-path="url(#clip-signal)"><path class="line-rsrp" d="${path(points,x,yr,'rsrp')}"/><path class="line-sinr" d="${path(points,x,ys,'sinr')}"/></g>${this.axis(start,span,f)}${this.cursor('signal',points,x,{sinr:ys,rsrp:yr},['sinr','rsrp'],f)}`;
  }
 }
 // Time ticks fall on round clock times and scroll with the data.
 axis(start,span,f){
  const step=TIME_STEPS[this.window],x=t=>f.left+(t-start)/span*(f.right-f.left);let out='';
  for(let t=Math.ceil(start/step)*step;t<=start+span;t+=step){const px=x(t);if(px<f.left+18||px>f.right-18)continue;out+=`<line class="tick" x1="${px.toFixed(1)}" x2="${px.toFixed(1)}" y1="${f.bottom}" y2="${f.bottom+4}"/><text class="axis" x="${px.toFixed(1)}" y="${f.bottom+17}" text-anchor="middle">${timeLabel(t,this.window)}</text>`;}
  return `<line class="baseline" x1="${f.left}" x2="${f.right}" y1="${f.bottom}" y2="${f.bottom}"/>${out}`;
 }
 cursor(id,points,x,y,keys,f){
  const hover=this.hover[id];if(hover===undefined||!points.length)return '';
  const nearest=points.reduce((best,p)=>Math.abs(p.t-hover)<Math.abs(best.t-hover)?p:best,points[0]);
  const px=x(nearest.t);if(px<f.left||px>f.right)return '';
  const tip=this.$(`[data-chart-box=${id}] [data-tip]`);
  if(tip){
   const rows=id==='throughput'?`<span class="legend-dl">Download <b>${rate(mbps(nearest.dl))}</b> Mbps</span><span class="legend-ul">Upload <b>${rate(mbps(nearest.ul))}</b> Mbps</span>${finite(nearest.carriers)?`<span class="tip-meta">${fmt(nearest.carriers,1)} carriers in use${nearest.dl_mod?` · ${nearest.dl_mod}`:''}</span>`:''}`:`<span class="legend-sinr">SINR <b>${fmt(nearest.sinr)}</b> dB</span><span class="legend-rsrp">RSRP <b>${fmt(nearest.rsrp)}</b> dBm</span>`;
   morphHTML(tip,`<strong>${timeLabel(nearest.t,'30s')}</strong>${rows}`);
   tip.hidden=false;const ratio=px/f.width;tip.style.left=`${(ratio*100).toFixed(2)}%`;tip.dataset.side=ratio>.6?'left':'right';
  }
  const dots=keys.map(key=>{const v=nearest[key];if(!finite(v))return '';const fy=typeof y==='function'?y:y[key];return `<circle class="dot-${key}" cx="${px.toFixed(1)}" cy="${fy(v).toFixed(1)}" r="4"/>`;}).join('');
  return `<line class="cursor" x1="${px.toFixed(1)}" x2="${px.toFixed(1)}" y1="${f.top}" y2="${f.bottom}"/>${dots}`;
 }
 move(event){
  const svg=event.target.closest?.('[data-history]');if(!svg){this.leave();return;}
  const bounds=svg.getBoundingClientRect(),span=WINDOWS.find(w=>w[0]===this.window)[2],now=this.window==='30s'?Date.now()-1000:Date.now();
  const f=this.chartBox(svg,svg.dataset.history==='signal'?46:12),px=(event.clientX-bounds.left)/bounds.width*f.width;
  this.hover={[svg.dataset.history]:now-span+(px-f.left)/(f.right-f.left)*span};
  if(this.window!=='30s')this.draw(Date.now());
 }
 leave(){if(!Object.keys(this.hover).length)return;this.hover={};this.$$('[data-tip]').forEach(tip=>tip.hidden=true);if(this.window!=='30s')this.draw(Date.now());}
 paintMap(gps){
  const map=this.$('[data-map]');if(!map)return;
  const fix=!!gps?.fix&&finite(gps.latitude)&&finite(gps.longitude);
  map.classList.toggle('has-fix',fix);
  this.$('[data-map-wait]').hidden=fix;this.$('[data-map-marker]').hidden=!fix;
  const status=this.$('[data-gps-status]'),statusText=!gps?'Waiting for GPS':fix?`GPS fix${gps.updated?` · ${new Date(gps.updated).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})}`:''}`:'Searching for satellites';if(status.textContent!==statusText)status.textContent=statusText;
  const set=(key,value)=>{const el=this.$(`[data-gps=${key}]`);if(el&&el.textContent!==value)el.textContent=value;};
  set('latitude',fix?`${Math.abs(gps.latitude).toFixed(5)}° ${gps.latitude>=0?'N':'S'}`:'—');set('longitude',fix?`${Math.abs(gps.longitude).toFixed(5)}° ${gps.longitude>=0?'E':'W'}`:'—');set('altitude',fix&&finite(gps.altitude_m)?`${gps.altitude_m.toFixed(0)} m`:'—');
  const link=this.$('[data-gps=link]');link.hidden=!fix;this.$('[data-gps=nolink]').hidden=fix;if(fix)link.href=`https://www.openstreetmap.org/?mlat=${gps.latitude.toFixed(6)}&mlon=${gps.longitude.toFixed(6)}#map=${this.zoom}/${gps.latitude.toFixed(5)}/${gps.longitude.toFixed(5)}`;
  if(!fix)return;
  const key=`${gps.latitude.toFixed(5)},${gps.longitude.toFixed(5)},${this.zoom},${map.clientWidth}x${map.clientHeight}`;if(key===this.tiles)return;this.tiles=key;
  // Web Mercator tiles centered on the unit.
  const z=this.zoom,n=2**z,lat=gps.latitude*Math.PI/180,fx=(gps.longitude+180)/360*n,fy=(1-Math.log(Math.tan(lat)+1/Math.cos(lat))/Math.PI)/2*n;
  const w=map.clientWidth||400,h=map.clientHeight||260,cx=w/2,cy=h/2,size=256;
  const x0=Math.floor(fx-cx/size)-0,x1=Math.floor(fx+cx/size),y0=Math.floor(fy-cy/size),y1=Math.floor(fy+cy/size);
  const tiles=[];
  for(let tx=x0;tx<=x1;tx++)for(let ty=y0;ty<=y1;ty++){if(ty<0||ty>=n)continue;const wx=((tx%n)+n)%n;tiles.push(`<img alt="" draggable="false" loading="lazy" decoding="async" src="https://tile.openstreetmap.org/${z}/${wx}/${ty}.png" style="left:${(cx+(tx-fx)*size).toFixed(1)}px;top:${(cy+(ty-fy)*size).toFixed(1)}px">`);}
  this.$('[data-map-tiles]').innerHTML=tiles.join('');
 }
}
