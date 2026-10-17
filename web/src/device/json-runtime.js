import {witcherLabel,witcherVersion} from '../version.js';
import {watchFirmwareVersion,rememberFirmwareReturn,firmwareReturnNotice,freshFirmwareUrl} from './firmware-reconnect.js';
import {SessionExpired} from './errors.js';
import {JsonSettingsView,prefetchSettings,cachedSettings,clearSettingsCache} from './json-settings-view.js';
import {DiagnosticsView,DIAGNOSTIC_TOOLS} from './diagnostics-view.js';
import {jsonRequest,session,logout,parseJsonTelemetry,SampleClock} from './json-client.js';
const routes={
 radio:{apn:'APN profiles',selection:'Band & selection',lock:'PCI lock',scan:'Cell scan'},
 network:{mode:'Operating mode',lan:'LAN & DHCP',firewall:'Firewall',forwards:'Port forwards',routes:'Routes'},
 system:{device:'Device',access:'Access',ssh:'SSH keys',services:'ACS',sas:'SAS',cpi:'CPI',sasStatus:'CBSD status',backup:'Backup',firmware:'Firmware',restart:'Restart'},
 diagnostics:{ping:'Ping',traceroute:'Traceroute',status:'Network status'}
};
const systemGroups=[['device','Device',['device','backup','restart']],['access','Access',['access','ssh']],['services','ACS',['services']],['sas','SAS',['sas','cpi','sasStatus']],['firmware','Firmware',['firmware']]];
export function createDeviceRuntime(h){
 const {state,config,esc}=h;let epoch=0;let timer,stopVersionWatch,fetching=false,last=0,telem=null,logged=false,starting=true,macRequest=null;
 let source=new SampleClock();
 state.scenario='stale';state.pci=null;state.ethernetSpeed=null;state.tabs.diagnostics='ping';
 config.name='Titan 4000';config.mode='—';config.ipType='—';config.pciMode='Automatic';
 const q=s=>document.querySelector(s),qa=s=>[...document.querySelectorAll(s)];
 const message=msg=>h.confirmDialog('Titan device',esc(msg),()=>{},'Close');
 const native=new JsonSettingsView({state,toast:h.toast,message,table:(title,rows)=>h.confirmDialog(title,`<div class="device-table-wrap"><table class="device-table">${rows.map((row,i)=>`<tr>${row.map(cell=>`<${i?'td':'th'}>${esc(cell)}</${i?'td':'th'}>`).join('')}</tr>`).join('')}</table></div>`,()=>{},'Close'),confirm:(msg,yes)=>h.confirmDialog('Apply to this Titan?',esc(msg),yes,'Continue'),expire,loaded:()=>q('[data-native-loading]')?.remove()});
 const diagnostics=new DiagnosticsView({toast:h.toast,expire,esc});
 const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
 const sectionFor=({page,tab}={})=>{const pages=routes[page];if(!pages)return null;const id=tab??state.tabs[page];return pages[id]?id:Object.keys(pages)[0];};
 // Resolves when the target screen can render complete, or after a short wait
 // so a slow unit never makes a click feel ignored.
 function prepare(target){
  const section=sectionFor(target);if(!section||!logged)return Promise.resolve();
  if(DIAGNOSTIC_TOOLS.includes(section)){diagnostics.prefetch();return Promise.resolve();}
  if(cachedSettings(section))return Promise.resolve();
  return Promise.race([prefetchSettings(section),pause(900)]);
 }
 function prefetch(target){const section=sectionFor(target);if(!section||!logged)return;if(DIAGNOSTIC_TOOLS.includes(section))diagnostics.prefetch();else prefetchSettings(section,{maxAge:15000}).catch(()=>{});}
 // After sign-in, read every settings screen once in the background, current
 // page first, so later navigation is instant.
 async function warm(){
  const generation=epoch,order=[...new Set([...Object.keys(routes[state.page]||{}),...Object.values(routes).map(p=>Object.keys(p)[0]),...Object.values(routes).flatMap(p=>Object.keys(p))])].filter(id=>!DIAGNOSTIC_TOOLS.includes(id));
  await pause(600);
  for(const section of order){
   if(generation!==epoch||!logged)return;
   if(document.hidden||native.busy){await pause(1000);continue;}
   try{await prefetchSettings(section,{maxAge:60000});}catch(error){if(error instanceof SessionExpired)return;}
   await pause(150);
  }
 }
 function expire(){if(native.busy&&native.section==='firmware')return;epoch++;logged=false;telem=null;latest=null;rtt=0;Object.assign(legacy,{key:null,seq:0,t:0,qkey:null,qseq:0,signal:null,quality:null});source=new SampleClock();state.dirty=false;state.scenario='stale';state.page='login';native.destroy();diagnostics.reset();clearSettingsCache();history.replaceState(null,'','#login');h.shell();decorateLogin();}
 function decorateLogin(){
  q('.login-topline span').textContent='Titan 4000';q('.login-submit').firstChild.textContent='Sign in ';
  const input=q('#login-password');input.required=true;input.autocomplete='current-password';
  q('#preview-login').textContent=firmwareReturnNotice(witcherVersion)||'Sign in with the device password.';
  q('.login-photo').style.backgroundImage=`url('/ui/titan-rooftop.jpg')`;
  q('.login-version').textContent=witcherLabel;
  const mac=q('[data-login-mac]');
  if(!macRequest)macRequest=fetch('/ui/device-mac.txt',{cache:'no-store',credentials:'omit',signal:AbortSignal.timeout(5000)})
   .then(async response=>{if(!response.ok)throw Error('MAC unavailable');const value=(await response.text()).trim();return /^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(value)?value.toUpperCase():'Unavailable';})
   .catch(()=>{macRequest=null;return 'Unavailable';});
  macRequest.then(value=>{if(mac?.isConnected)mac.textContent=value;});
 }
 function acceptTelemetry(next,{newSample=true,sampledAt=Date.now(),stale=false}={}){
   telem=next;
   logged=true;last=sampledAt;
   Object.assign(config,{name:next.name,mode:next.mode,ipType:next.ipType});
   Object.assign(state,{scenario:stale||Date.now()-last>=8000?'stale':next.attached?'connected':'searching',pci:next.pci,ethernetSpeed:next.ethernet,rsrp:next.rsrp,sinr:next.sinr,rsrq:next.rsrq,tick:next.session,lastUpdate:last,sasRegistration:next.registration,sasGrant:next.grant});
   if(fresh()&&newSample)h.tick();else{if(!fresh())h.stopCapture('stale');h.updateLive();}
 }
 async function poll(){
  if(native.busy&&native.section==='firmware'||fetching||document.hidden&&!starting||(!logged&&!starting))return false;fetching=true;const generation=epoch;
  try{
   const began=Date.now();
   const sample=parseJsonTelemetry(await jsonRequest('/api/v1/telemetry'));
   const receivedAt=Date.now(),next=sample.telemetry;
   if(generation!==epoch)return false;
   rtt=receivedAt-began;
   const newSample=source.accept(sample,receivedAt,rtt);
   // Render and subscriber errors are view bugs, not failed polls: they must never mark telemetry stale.
   const guard=f=>{try{f();}catch(error){console.error(error);}};
   guard(()=>acceptTelemetry(next,{newSample,sampledAt:source.sampledAt,stale:sample.stale}));
   latest=build(sample,receivedAt);
   listeners.forEach(f=>guard(()=>f(latest)));
   return true;
  }catch(error){
   if(generation!==epoch)return false;state.scenario='stale';
   // One dropped request should not throw away a mark; the 8 s staleness rule catches real outages.
   if(error instanceof SessionExpired){if(native.busy&&native.section==='firmware')return false;h.stopCapture('expired');h.updateLive();expire();}else h.updateLive();
   return false;
  }finally{fetching=false;}
 }
 // Align source (spec 2.3). Device clocks are mapped to the browser clock with
 // half the round trip; an older backend without radio.signal falls back to
 // value changes, plus a heartbeat so a frozen modem never looks fresh forever.
 const listeners=new Set();let latest=null,rtt=0;const legacy={key:null,seq:0,t:0,qkey:null,qseq:0,signal:null,quality:null};
 // Age and pause are re-read on every call: polls can fail for seconds while the
 // screen keeps asking, and a pause click must show before the next poll.
 let aged=null;
 const align={kind:'device',subscribe(fn){listeners.add(fn);return ()=>listeners.delete(fn);},
  snapshot(){
   if(!latest)return null;const stale=latest.stale||Date.now()-last>=8000||!source.fresh(),paused=!!state.paused;
   if(aged?.base!==latest||aged.s.stale!==stale||aged.s.paused!==paused)aged={base:latest,s:{...latest,stale,paused,connected:latest.connected&&!stale}};
   return aged.s;
  }};
 const num=v=>typeof v==='number'&&Number.isFinite(v)?v:null,arr=v=>Array.isArray(v)?v.map(num):[];
 function legacySignal(t,connected){
  const chains=(t.chains||[]).slice(0,2).filter(Number.isFinite),key=JSON.stringify([t.chains?.[0]??null,t.chains?.[1]??null,t.rsrq,t.sinr]),now=Date.now();
  if(!connected&&legacy.key===null)return {signal:null,quality:null};
  if(key!==legacy.key||connected&&now-legacy.t>15000){
   const heartbeat=key===legacy.key;legacy.key=key;legacy.seq++;legacy.t=source.sampledAt;
   legacy.signal={seq:legacy.seq,reading:legacy.seq,t:legacy.t,readingT:legacy.t,rsrp:chains.length?chains:Number.isFinite(t.rsrp)?[t.rsrp]:[],rsrq:Number.isFinite(t.rsrq)?[t.rsrq]:[],rssi:[],heartbeat,source:'legacy',periodMs:null};
  }
  const qkey=JSON.stringify(t.sinr);
  if(qkey!==legacy.qkey&&Number.isFinite(t.sinr)){legacy.qkey=qkey;legacy.qseq++;legacy.quality={seq:legacy.qseq,t:source.sampledAt,cinr:null,sinr:t.sinr,sinrStep:1,source:'legacy'};}
  return {signal:legacy.signal,quality:legacy.quality};
 }
 function build(sample,receivedAt){
  const t=sample.telemetry,radio=t.radio||{},half=rtt/2,stale=sample.stale||Date.now()-last>=8000;
  const connected=!!(logged&&t.attached&&[t.rsrp,t.sinr,t.rsrq].every(Number.isFinite)&&!stale&&source.fresh());
  // A backend that knows the watch keys reports them even when null (stale broker): that is "no reading",
  // never a cue to fall back to value-change detection, which would count a frozen value as fresh.
  const watchCapable='signal' in radio||'quality' in radio;
  const sig=radio.signal,qual=radio.quality,old=watchCapable?null:legacySignal(t,connected);
  return {kind:'device',receivedAt,collectedAt:source.sampledAt,connected,attached:!!t.attached,stale,paused:!!state.paused,
   cell:{pci:num(t.pci),earfcn:Number(t.earfcn)||null,band:t.band||null,enbId:num(radio.enb_id),cellId:num(radio.cell_id),tac:num(radio.tac),eci:num(radio.eci)},
   signal:sig?{seq:sig.seq,reading:sig.reading,t:receivedAt-half-(sig.age_ms||0),readingT:receivedAt-half-(sig.reading_age_ms??sig.age_ms??0),rsrp:arr(sig.rsrp),rsrq:arr(sig.rsrq),rssi:arr(sig.rssi),heartbeat:false,source:'watch',periodMs:num(sig.period_ms)}:old?old.signal:null,
   quality:qual?{seq:qual.seq,t:receivedAt-half-(qual.age_ms||0),cinr:Array.isArray(qual.cinr)?arr(qual.cinr):null,sinr:num(qual.sinr),sinrStep:num(qual.sinr_step_db)??1,source:'watch'}:old?old.quality:null,
   activeChains:num(radio.active_chains)??2,
   neighbours:(Array.isArray(radio.neighbours)?radio.neighbours:[]).map(n=>({earfcn:n.earfcn,pci:n.pci,rsrp:n.rsrp,rsrq:num(n.rsrq),rssi:num(n.rssi),coChannel:n.co_channel??null})),
   carriers:(Array.isArray(radio.carriers)?radio.carriers:[]).map(c=>({role:c.role,index:c.index,earfcn:num(c.earfcn),pci:num(c.pci),bandwidthMhz:num(c.bandwidth_mhz),sinr:num(c.sinr),
    rsrpChains:arr(c.rsrp_chains),rsrqChains:arr(c.rsrq_chains),rssiChains:arr(c.rssi_chains),cinrChains:arr(c.cinr_chains),active:c.active!==false,dlModulation:c.dl_modulation??null,dlMcs:num(c.dl_mcs)})),
   radio:{cqi:num(radio.cqi),ri:num(radio.ri),dlModulation:radio.dl?.modulation??null,dlMcs:num(radio.dl?.mcs),ulModulation:radio.ul?.modulation??null,ulMcs:num(radio.ul?.mcs),
    configured:num(radio.configured_carriers)??(t.attached?1:0),active:num(radio.active_carriers)??(t.attached?1:0),txPowerDbm:num(radio.tx_power_dbm),mimo:radio.mimo??null},
   throughput:{dlBps:num(t.throughput?.dl_bps),ulBps:num(t.throughput?.ul_bps)},
   sas:{grant:t.grant||'Unknown',registration:t.registration||'Unknown'},
   gps:t.gps?{fix:!!t.gps.fix,latitude:num(t.gps.latitude),longitude:num(t.gps.longitude),altitudeM:num(t.gps.altitude_m)}:null,
   refresh:radio.refresh?{pending:radio.refresh.pending??null,cycleMs:num(radio.refresh.cycle_ms)}:null};
 }
 function fresh(){return logged&&telem?.attached&&[telem.rsrp,telem.sinr,telem.rsrq].every(Number.isFinite)&&!state.paused&&state.scenario!=='stale'&&Date.now()-last<8000&&source.fresh();}
 function update(){
  if(!logged||state.page==='login')return;
  native.update();
  const healthy=state.scenario!=='stale'&&Date.now()-last<8000;
  const set=(selector,value)=>qa(selector).forEach(el=>{if(el.textContent!==String(value))el.textContent=value;});
  set('[data-device=serial]',telem?.serial||'—');set('[data-device=band]',telem?.band||'—');set('[data-device=earfcn]',telem?.earfcn||'—');
  set('[data-device=network]',telem?.plmn?`PLMN ${telem.plmn}`:'—');set('[data-device=management]',telem?.mgmt||'—');set('[data-device=customer]',telem?.customer||'—');
  set('[data-quality=uptime]','LTE session');
  set('[data-health=sas]',healthy?telem?.grant||'Unknown':'Unknown');
  set('[data-health=data]',healthy?(telem?.customer?'Address assigned':'No address'):'Unknown');
  set('[data-ethernet-speed]',healthy&&telem?.ethernet!==null?(telem.ethernet===1000?'1 Gbps':`${telem.ethernet} Mbps`):'—');
  set('[data-health=ethernet]',healthy&&telem?.ethernet!==null?(telem.ethernet===1000?'1 Gbps':`${telem.ethernet} Mbps`):'Unknown');
  if(!healthy||telem?.ethernet===null){qa('[data-ethernet-link],[data-health=ethernet]').forEach(el=>el.classList.remove('ethernet-slow'));qa('[data-ethernet-notice]').forEach(el=>el.hidden=true);}
 }
 function values(){const available=fresh();return {rsrp:available?state.rsrp.toFixed(1):'—',sinr:available?state.sinr.toFixed(1):'—',rsrq:available?state.rsrq.toFixed(1):'—',pci:state.pci??'—',chains:available?telem.chains.slice(0,2).map(v=>v===null?'—':v.toFixed(1)).join(' / '):'—',uptime:`${Math.floor(state.tick/3600)}h ${Math.floor(state.tick%3600/60)}m ${state.tick%60}s`};}
 function renderPage({head,tabs}){
  const pages=routes[state.page];if(!pages)return undefined;
  if(!pages[state.tabs[state.page]])state.tabs[state.page]=Object.keys(pages)[0];
  const titles={radio:['Radio','Manage bearers, radio preferences and PCI selection.'],network:['Network','Operating mode, local networking and routing.'],system:['System','Device settings, operator access and maintenance.'],diagnostics:['Diagnostics','Run checks from the Titan and inspect connection status.']};
  const [title,subtitle]=titles[state.page];
  let navigation=tabs(state.page,Object.entries(pages)),secondary='';
  if(state.page==='system'){
   const current=state.tabs.system,group=systemGroups.find(g=>g[2].includes(current));
   navigation=`<div class="panel-tabs" data-tablist="system" role="tablist" aria-label="System sections">${systemGroups.map(([id,label,keys])=>`<button role="tab" data-system-group="${id}" data-tab="${id}" data-section="system" aria-selected="${keys.includes(current)}" class="${keys.includes(current)?'active':''}">${label}</button>`).join('')}<span class="tab-indicator" aria-hidden="true"></span></div>`;
   if(group[2].length>1)secondary=`<div class="settings-subnav" role="tablist" aria-label="${group[1]} sections">${group[2].map(id=>`<button role="tab" aria-selected="${id===current}" class="${id===current?'active':''}" data-tab="${id}" data-section="system">${id==='device'?'Password & time':id==='access'?'Management':id==='sas'?'Configuration':id==='cpi'?'CPI installation':pages[id]}</button>`).join('')}</div>`;
  }
  return `${head('',title,subtitle)}${navigation}<div data-tab-panel="${state.page}">${secondary}<div data-native-host></div></div>`;
 }
 function mount(){
  if(state.page==='login'){native.destroy();decorateLogin();return;}
  q('.preview-context').innerHTML=`<span class="live-unit-label">${esc(telem?.serial||'Titan 4000')}</span><span>Live device</span>`;
  q('.header-demo')?.remove();q('[data-action=tour]')?.remove();q('.side-unit>span').textContent='LIVE DEVICE';q('.side-unit strong').textContent=config.name;
  q('.edition').textContent=witcherLabel;q('.footer').innerHTML=`<span>${esc(witcherLabel)} / Base ${esc(telem?.firmware||'—')}</span><span><a href="/ui/licenses/index.html" target="_blank" rel="noopener">Software licenses</a> · <a href="/#system" target="_blank" rel="noopener">Backup & recovery ↗</a></span>`;
  q('[data-action=logout]').setAttribute('aria-label','Sign out');
  if(state.page==='system'){
   qa('[data-system-group]').forEach(el=>{const active=systemGroups.find(g=>g[0]===el.dataset.systemGroup)[2].includes(state.tabs.system);el.classList.toggle('active',active);el.setAttribute('aria-selected',String(active));});
   const selected=q('[data-system-group].active'),indicator=q('[data-tablist=system] .tab-indicator');if(selected&&indicator){indicator.style.width=selected.offsetWidth+'px';indicator.style.transform=`translateX(${selected.offsetLeft}px)`;}
  }
  q('[data-health=data]')?.closest('.health-row')?.querySelector('small')?.replaceChildren(document.createTextNode('Customer bearer address'));
  const page=routes[state.page]?.[state.tabs[state.page]],host=q('[data-native-host]'),section=state.tabs[state.page];
  if(page&&host&&state.page==='diagnostics'&&DIAGNOSTIC_TOOLS.includes(section)){native.destroy();diagnostics.mount(host,section);}
  else{if(state.page!=='diagnostics')diagnostics.destroy();else diagnostics.detach();if(page&&host)native.mount(host,section);else native.destroy();}
  update();
 }
 async function submit(form){
  if(form.dataset.form!=='login'){h.toast('This control is not connected to a device handler.');return;}
  const button=form.querySelector('[type=submit]');button.disabled=true;
  try{await session(q('#login-password').value);form.reset();logged=true;starting=true;const ready=await poll();starting=false;if(!logged||!ready)throw new Error('Login returned without an authenticated session.');state.dirty=false;h.nav('overview');warm();}
  catch(e){h.toast(e.message);}
  finally{button.disabled=false;}
 }
 async function start(){
  stopVersionWatch?.();
  stopVersionWatch=watchFirmwareVersion(witcherVersion,{canReload:()=>!native.busy&&!state.dirty,onChange:version=>{
   rememberFirmwareReturn(version,'updated');window.location.replace(freshFirmwareUrl());
  }});
  const requested=location.hash.slice(1);
  state.page='booting';
  q('#app').innerHTML='<div class="device-boot"><span class="boot-wordmark">TITAN</span><span class="boot-track" aria-hidden="true"></span><p role="status">Connecting to your Titan…</p></div>';
  try{await session();logged=true;}catch(error){if(error instanceof SessionExpired)expire();}
  if(logged)await poll();
  starting=false;
  if(logged){state.page=['overview','align',...Object.keys(routes)].includes(requested)?requested:'overview';history.replaceState(null,'','#'+state.page);await prepare({page:state.page});h.transitionContent(()=>h.shell(),{auth:true});warm();}
  else if(state.page!=='login'){
   q('#app').innerHTML='<div class="device-boot"><span class="boot-wordmark">TITAN</span><h1>Connection unavailable</h1><p>Check your connection to the Titan, then try again.</p><button class="btn btn-primary" data-device-retry>Try again</button></div>';
   q('[data-device-retry]').onclick=()=>{starting=true;start();};return;
  }
  clearInterval(timer);timer=setInterval(()=>{if(logged){if(Date.now()-last>8000){state.scenario='stale';h.stopCapture('stale');h.updateLive();}poll();}},1000);
 }
 const oldTheme=h.handlers.theme;h.handlers.theme=()=>{oldTheme();native.theme();};
 h.handlers.logout=async()=>{try{await logout();}catch(error){if(!(error instanceof SessionExpired)){h.toast('Could not sign out. Check the connection and try again.');return;}}expire();};
  // Normalized live reading and stored history for the Overview dashboard.
 const dashboard={
  live(){
   if(!telem)return null;const radio=telem.radio||{},carriers=Array.isArray(radio.carriers)?radio.carriers:[];
   const num=v=>typeof v==='number'&&Number.isFinite(v)?v:null;
   return {fresh:fresh(),attached:telem.attached,sampledAt:last,dl_bps:num(telem.throughput?.dl_bps),ul_bps:num(telem.throughput?.ul_bps),rsrp:telem.rsrp,sinr:telem.sinr,rsrq:telem.rsrq,cqi:num(radio.cqi),ri:num(radio.ri),dl:radio.dl||null,ul:radio.ul||null,
    configured:num(radio.configured_carriers)??(telem.attached?1:0),active:num(radio.active_carriers)??(telem.attached?1:0),carriers,bandwidth:carriers.reduce((sum,c)=>sum+(num(c.bandwidth_mhz)||0),0)||null,radioAge:num(radio.age_ms),gps:telem.gps||null};
  },
  history(window){return jsonRequest('/api/v1/history?window='+encodeURIComponent(window),{signal:AbortSignal.timeout(10000)});}
 };
 return {dashboard,align,get busy(){return native.busy;},prepare,prefetch,start,renderPage,mount,update,values,submit,fresh,get authenticated(){return logged;},get telemetry(){return telem;}};
}
