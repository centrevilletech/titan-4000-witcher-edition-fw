import {apiFetch,jsonRequest} from './json-client.js';
import {SessionExpired} from './errors.js';
import {morphHTML} from '../morph.js';

// Ping and traceroute run on the Titan and stream one JSON event per line.
// Each output line reaches the screen as the tool prints it; aborting the
// request is the stop button, and the unit ends the process when it sees that.
export const DIAGNOSTIC_TOOLS=['ping','traceroute'];
const STORE='titan-diagnostics-options';
const LIMITS={ping:{count_max:1000,size_max:1472,ttl_max:255},traceroute:{hops_max:64,probes_max:5,wait_max:10}};
const DEFAULTS={
 ping:{destination:'',family:'ipv4',count:5,continuous:false,size:56,ttl:'',timeout:2,interface:''},
 traceroute:{destination:'',family:'ipv4',max_hops:30,probes:3,wait:3,protocol:'icmp',resolve:true,interface:''}
};
const MAX_LINES=2000;
const esc=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const ms=value=>value===null||value===undefined||!Number.isFinite(value)?'—':value<10?value.toFixed(2):value<100?value.toFixed(1):Math.round(value).toString();
const seconds=value=>value<60?`${value.toFixed(value<10?1:0)}s`:`${Math.floor(value/60)}m ${Math.floor(value%60)}s`;
const isAddress=token=>/^\d{1,3}(\.\d{1,3}){3}$/.test(token)||token.includes(':')&&/^[0-9a-f:.]+$/i.test(token);
const validHost=value=>value.length>0&&value.length<=253&&!value.startsWith('-')&&/^[A-Za-z0-9.:-]+$/.test(value);
function loadOptions(){
 let stored={};try{stored=JSON.parse(localStorage.getItem(STORE))||{};}catch{}
 return {ping:{...DEFAULTS.ping,...stored.ping},traceroute:{...DEFAULTS.traceroute,...stored.traceroute}};
}

export function parsePingLine(run,text){
 const reply=text.match(/^(\d+) bytes from (.+?): seq=(\d+) ttl=(\d+) time=([\d.]+) ms(.*)$/);
 if(reply){
  const seq=Number(reply[3]),duplicate=/DUP/.test(reply[6])||run.seen.has(seq);
  if(!run.from)run.from=reply[2];
  if(!duplicate){run.seen.add(seq);run.replies.push({seq,ttl:Number(reply[4]),time:Number(reply[5])});}
  else run.duplicates++;
  run.maxSeq=Math.max(run.maxSeq,seq);
  return;
 }
 const header=text.match(/^PING (\S+) \(([^)]+)\)/);if(header){run.resolved=header[2];return;}
 const totals=text.match(/(\d+) packets transmitted, (\d+) packets received(?:, \+?(\d+) duplicates)?, (\d+)% packet loss/);
 if(totals){run.summary={...run.summary,transmitted:Number(totals[1]),received:Number(totals[2]),loss:Number(totals[4])};return;}
 const trip=text.match(/round-trip min\/avg\/max = ([\d.]+)\/([\d.]+)\/([\d.]+) ms/);
 if(trip)run.summary={...run.summary,min:Number(trip[1]),avg:Number(trip[2]),max:Number(trip[3])};
}
export function parseTracerouteLine(run,text){
 const header=text.match(/^traceroute6? to (\S+) \(([^)]+)\)/);if(header){run.resolved=header[2];return;}
 const line=text.match(/^\s*(\d+)\s+(.*)$/);if(!line)return;
 const number=Number(line[1]),tokens=line[2].replace(/[()]/g,' ').trim().split(/\s+/);
 const hop={hop:number,probes:[],addresses:[]};let address=null;
 for(let i=0;i<tokens.length;i++){
  const token=tokens[i];
  if(token==='*')hop.probes.push({address,rtt:null});
  else if(isAddress(token)){address=token;if(!hop.addresses.includes(token))hop.addresses.push(token);}
  else if(/^[\d.]+$/.test(token)&&tokens[i+1]==='ms'){hop.probes.push({address,rtt:Number(token)});i++;}
  else if(/^![A-Za-z0-9]*$/.test(token)&&hop.probes.length)hop.probes.at(-1).note=token;
 }
 run.hops.set(number,hop);
 if(run.resolved&&hop.addresses.includes(run.resolved))run.reached=true;
}

export class DiagnosticsView {
 constructor(h){this.h=h;this.host=null;this.tool=null;this.meta=null;this.metaRequest=null;this.runs={};this.options=loadOptions();this.frame=0;this.clock=0;}
 prefetch(){
  if(this.meta)return Promise.resolve(this.meta);
  this.metaRequest??=jsonRequest('/api/v1/diagnostics',{signal:AbortSignal.timeout(8000)}).then(meta=>{this.meta=meta;if(this.host)this.paintForm();return meta;}).catch(error=>{if(error instanceof SessionExpired)this.h.expire();return null;}).finally(()=>{this.metaRequest=null;});
  return this.metaRequest;
 }
 limits(tool){return {...LIMITS[tool],...this.meta?.limits?.[tool]};}
 mount(host,tool){
  this.host=host;this.tool=tool;
  host.onsubmit=event=>{event.preventDefault();this.running(tool)?this.stop(tool):this.start(tool);};
  host.onclick=event=>this.click(event);
  host.oninput=host.onchange=event=>this.input(event);
  host.innerHTML=this.view(tool);
  this.paint();this.prefetch();this.tick();
 }
 detach(){this.host=null;this.tool=null;cancelAnimationFrame(this.frame);clearInterval(this.clock);}
 destroy(){
  const active=DIAGNOSTIC_TOOLS.filter(tool=>this.running(tool));
  for(const tool of active)this.runs[tool].controller.abort();
  if(active.length)this.h.toast(`${active.map(tool=>tool==='ping'?'Ping':'Traceroute').join(' and ')} stopped.`);
  this.detach();
 }
 reset(){for(const run of Object.values(this.runs))run?.controller?.abort();this.runs={};this.meta=null;this.detach();}
 running(tool){return this.runs[tool]?.state==='running';}
 tick(){clearInterval(this.clock);this.clock=setInterval(()=>{if(this.host&&this.running(this.tool))this.schedule();},500);}
 save(){try{localStorage.setItem(STORE,JSON.stringify(this.options));}catch{}}

 // Static structure. Results and controls are patched in place afterward.
 view(tool){
  const ping=tool==='ping';
  return `<form class="diag" data-diag="${tool}" novalidate autocomplete="off">
   <section class="card card-pad diag-setup">
    <header class="diag-head"><div><h2>${ping?'Ping':'Traceroute'}</h2><p>${ping?'Send ICMP echo requests from the Titan and watch each reply arrive.':'Follow the path from the Titan to a destination, one hop at a time.'}</p></div><span class="diag-state" data-diag-state></span></header>
    <div class="diag-fields" data-diag-fields></div>
    <div class="diag-actions"><button type="submit" class="btn btn-primary diag-run" data-diag-run></button><button type="button" class="btn" data-diag-clear>Clear</button><button type="button" class="btn" data-diag-copy>Copy output</button><span class="diag-command" data-diag-command></span></div>
    <div class="device-error" role="alert" data-diag-error hidden></div>
   </section>
   <div data-diag-results></div>
  </form>`;
 }
 fields(tool){
  const o=this.options[tool],l=this.limits(tool),disabled=this.running(tool)?'disabled':'';
  const interfaces=[{value:'',label:'Automatic'},...(this.meta?.interfaces||[]).filter(i=>i.value)];
  if(o.interface&&!interfaces.some(i=>i.value===o.interface))interfaces.push({value:o.interface,label:o.interface});
  const number=(name,label,min,max,help='',placeholder='')=>`<label class="field device-field"><span>${label}</span><input type="number" name="${name}" min="${min}" max="${max}" step="1" value="${esc(o[name])}" ${placeholder?`placeholder="${placeholder}"`:''} ${disabled} inputmode="numeric">${help?`<small>${help}</small>`:''}</label>`;
  const select=(name,label,options)=>`<label class="field device-field"><span>${label}</span><select name="${name}" ${disabled}>${options.map(([value,text])=>`<option value="${esc(value)}" ${String(o[name])===String(value)?'selected':''}>${esc(text)}</option>`).join('')}</select></label>`;
  const destination=`<label class="field device-field diag-destination"><span>Destination</span><input type="text" name="destination" value="${esc(o.destination)}" placeholder="8.8.8.8, 2001:4860:4860::8888 or example.com" spellcheck="false" autocapitalize="off" maxlength="253" required ${disabled}></label>`;
  const family=select('family','IP family',[['ipv4','IPv4'],['ipv6','IPv6']]);
  const source=select('interface','Source interface',interfaces.map(i=>[i.value,i.label]));
  if(tool==='ping')return `${destination}${family}
   <div class="field device-field"><span>Count</span><div class="diag-count"><input type="number" name="count" min="1" max="${l.count_max}" step="1" value="${esc(o.count)}" aria-label="Packet count" ${disabled||o.continuous?'disabled':''} inputmode="numeric"><label class="diag-check"><input type="checkbox" name="continuous" ${o.continuous?'checked':''} ${disabled}>Until stopped</label></div><small>${o.continuous?`Runs until you stop it (at most ${l.count_max}).`:`One per second, up to ${l.count_max}.`}</small></div>
   ${number('size','Packet size',0,o.family==='ipv6'?Math.min(l.size_max,1452):l.size_max,'Data bytes. 56 is standard.')}
   ${number('ttl','TTL',1,l.ttl_max,'','Default')}
   ${number('timeout','Reply timeout',1,10,'Seconds to wait after the last packet.')}
   ${source}`;
  return `${destination}${family}
   ${number('max_hops','Max hops',1,l.hops_max)}
   ${number('probes','Probes per hop',1,l.probes_max)}
   ${number('wait','Probe timeout',1,l.wait_max,'Seconds to wait for each reply.')}
   ${select('protocol','Probe type',[['icmp','ICMP echo'],['udp','UDP']])}
   ${source}
   <label class="device-toggle diag-resolve"><span>Resolve hostnames<small>Look up reverse DNS for each hop. Addresses appear first; names fill in as they resolve.</small></span><input type="checkbox" name="resolve" ${o.resolve?'checked':''} ${disabled}></label>`;
 }
 paintForm(){
  const fields=this.host?.querySelector('[data-diag-fields]');if(!fields)return;
  morphHTML(fields,this.fields(this.tool));
 }
 paint(){
  if(!this.host?.isConnected)return;
  const tool=this.tool,run=this.runs[tool],active=this.running(tool);
  this.paintForm();
  const button=this.host.querySelector('[data-diag-run]');
  button.classList.toggle('btn-primary',!active);button.classList.toggle('btn-stop',active);
  button.textContent=active?'Stop':run?'Run again':'Start';
  this.host.querySelector('[data-diag-clear]').disabled=active||!run;
  this.host.querySelector('[data-diag-copy]').disabled=!run?.lines.length;
  const command=this.host.querySelector('[data-diag-command]');command.textContent=run?.command||'';command.title=run?.command||'';
  const error=this.host.querySelector('[data-diag-error]'),message=run?.state==='error'?run.message:'';
  error.hidden=!message;if(error.textContent!==message)error.textContent=message;
  const status=this.host.querySelector('[data-diag-state]');
  morphHTML(status,this.status(run));
  const results=this.host.querySelector('[data-diag-results]');
  const log=results.querySelector('[data-diag-log]'),follow=!log||log.scrollHeight-log.scrollTop-log.clientHeight<24;
  morphHTML(results,run?(tool==='ping'?this.pingResults(run):this.traceResults(run)):'');
  const next=results.querySelector('[data-diag-log]');if(next&&follow)next.scrollTop=next.scrollHeight;
 }
 schedule(){if(this.frame)return;this.frame=requestAnimationFrame(()=>{this.frame=0;this.paint();});}
 status(run){
  if(!run)return '';
  const elapsed=((run.endedAt||Date.now())-run.startedAt)/1000;
  if(run.state==='running')return `<span class="diag-live"><i></i>${run.waiting?'Waiting for replies':'Running'} · ${seconds(elapsed)}</span>`;
  if(run.state==='stopped')return `<span class="pill pill-neutral">Stopped after ${seconds(elapsed)}</span>`;
  if(run.state==='error')return `<span class="pill pill-amber">Did not finish</span>`;
  return `<span class="pill ${run.ok===false?'pill-amber':'pill-green'}">${run.ok===false?'No reply':'Completed'} in ${seconds(elapsed)}</span>`;
 }
 log(run){
  const lines=run.lines.slice(-MAX_LINES);
  return `<details class="diag-raw" ${run.showRaw??run.tool==='ping'?'open':''} data-diag-raw><summary>Raw output <span>${run.lines.length} line${run.lines.length===1?'':'s'}</span></summary><div class="diag-log" data-diag-log role="log" aria-live="off">${lines.map(line=>`<div class="${line.stream==='stderr'?'diag-err':''}">${esc(line.text)||'&nbsp;'}</div>`).join('')}${run.state==='running'?'<div class="diag-cursor" aria-hidden="true"></div>':''}</div></details>`;
 }
 pingStats(run){
  const times=run.replies.map(r=>r.time),received=run.replies.length;
  const elapsed=((run.endedAt||Date.now())-(run.spawnedAt||run.startedAt))/1000;
  const sent=run.summary?.transmitted??Math.max(run.maxSeq+1,Math.min(run.count,run.spawnedAt?Math.floor(elapsed)+1:0));
  // While running, a packet only counts as lost once a later one has answered.
  const settled=run.summary?run.summary.transmitted:run.maxSeq+1;
  const lost=run.summary?run.summary.transmitted-run.summary.received:Math.max(0,settled-received);
  const loss=run.summary?run.summary.loss:settled?Math.round(lost/settled*100):null;
  const jitter=times.length>1?times.slice(1).reduce((sum,t,i)=>sum+Math.abs(t-times[i]),0)/(times.length-1):null;
  return {sent,received,lost,loss,min:times.length?Math.min(...times):null,avg:times.length?times.reduce((a,b)=>a+b,0)/times.length:null,max:times.length?Math.max(...times):null,jitter,last:times.at(-1)??null};
 }
 pingResults(run){
  const s=this.pingStats(run);
  const tile=(label,value,unit='',tone='')=>`<div class="diag-stat ${tone}"><span>${label}</span><strong>${value}<small>${unit}</small></strong></div>`;
  const window=60,first=Math.max(0,run.maxSeq+1-window),slots=[];
  for(let seq=first;seq<=run.maxSeq;seq++)slots.push(run.replies.find(r=>r.seq===seq)||null);
  const scale=Math.max(10,...slots.filter(Boolean).map(r=>r.time))*1.1,width=100/window;
  const bars=slots.map((reply,i)=>reply?`<rect class="diag-bar" x="${(i*width+width*.15).toFixed(2)}" y="${(100-reply.time/scale*100).toFixed(2)}" width="${(width*.7).toFixed(2)}" height="${(reply.time/scale*100).toFixed(2)}"><title>seq ${reply.seq}: ${ms(reply.time)} ms</title></rect>`:`<rect class="diag-miss" x="${(i*width+width*.15).toFixed(2)}" y="92" width="${(width*.7).toFixed(2)}" height="8"><title>seq ${first+i}: no reply</title></rect>`).join('');
  return `<section class="card card-pad diag-results">
   <div class="diag-stats">${tile('Last',ms(s.last),'ms')}${tile('Replies',`${s.received}<em>/${s.sent}</em>`)}${tile('Loss',s.loss===null?'—':s.loss,s.loss===null?'':'%',s.loss>0?'diag-warn':'')}${tile('Min / avg / max',`${ms(s.min)}<em>/</em>${ms(s.avg)}<em>/</em>${ms(s.max)}`,'ms')}${tile('Jitter',ms(s.jitter),'ms')}</div>
   <div class="diag-chart" aria-hidden="true"><svg viewBox="0 0 100 100" preserveAspectRatio="none">${bars}</svg><div class="diag-chart-scale"><span>${ms(scale)} ms</span><span>Last ${window} packets</span></div></div>
   ${run.from||run.resolved?`<p class="diag-meta">Replies from <span class="code">${esc(run.from||run.resolved)}</span>${run.duplicates?` · ${run.duplicates} duplicate${run.duplicates===1?'':'s'}`:''}</p>`:''}
   ${this.log(run)}
  </section>`;
 }
 traceResults(run){
  const hops=[...run.hops.values()].sort((a,b)=>a.hop-b.hop),resolve=run.options.resolve;
  const name=address=>{if(!resolve)return '';const value=run.names.get(address);return value===undefined?(run.state==='running'?'<span class="diag-resolving">Resolving…</span>':'<span class="muted">—</span>'):value?esc(value):'<span class="muted">—</span>';};
  const rows=hops.map(hop=>{
   const rtts=hop.probes.filter(p=>p.rtt!==null).map(p=>p.rtt),lost=hop.probes.length-rtts.length;
   const addresses=hop.addresses.length?hop.addresses:[null];
   return `<tr data-hop="${hop.hop}" class="${hop.addresses.includes(run.resolved)?'diag-target':''}"><td class="diag-hop">${hop.hop}</td><td class="code">${addresses.map(a=>`<div>${a?esc(a):'<span class="muted">No reply</span>'}</div>`).join('')}</td>${resolve?`<td class="diag-name">${addresses.map(a=>`<div>${a?name(a):''}</div>`).join('')}</td>`:''}<td><div class="diag-probes">${hop.probes.map(p=>p.rtt===null?'<span class="diag-probe diag-probe-miss">*</span>':`<span class="diag-probe">${ms(p.rtt)}${p.note?` ${esc(p.note)}`:''}</span>`).join('')}</div></td><td class="code">${rtts.length?ms(rtts.reduce((a,b)=>a+b,0)/rtts.length):'—'}</td><td class="${lost?'diag-warn':''}">${hop.probes.length?Math.round(lost/hop.probes.length*100)+'%':'—'}</td></tr>`;
  }).join('');
  const next=run.state==='running'&&!run.reached?`<tr class="diag-pending"><td class="diag-hop">${(hops.at(-1)?.hop||0)+1}</td><td colspan="${resolve?5:4}"><span class="diag-live"><i></i>Probing…</span></td></tr>`:'';
  const summary=run.reached?`Reached <span class="code">${esc(run.resolved)}</span> in ${hops.at(-1)?.hop} hop${hops.at(-1)?.hop===1?'':'s'}.`:run.state==='done'?`Did not reach ${esc(run.resolved||run.options.destination)} within ${run.options.max_hops} hops.`:run.resolved?`Tracing to <span class="code">${esc(run.resolved)}</span>…`:'';
  return `<section class="card card-pad diag-results">
   ${summary?`<p class="diag-meta">${summary}</p>`:''}
   <div class="device-table-wrap"><table class="device-table diag-hops"><thead><tr><th>Hop</th><th>Address</th>${resolve?'<th>Hostname</th>':''}<th>Probes (ms)</th><th>Avg</th><th>Loss</th></tr></thead><tbody>${rows}${next}${!rows&&!next?`<tr><td colspan="${resolve?6:5}" class="muted">No hops recorded.</td></tr>`:''}</tbody></table></div>
   ${this.log(run)}
  </section>`;
 }

 input(event){
  const tool=this.tool,target=event.target,name=target.name;
  if(!name||!(name in this.options[tool]))return;
  const o=this.options[tool];
  o[name]=target.type==='checkbox'?target.checked:target.value;
  this.save();
  if(event.type==='change'&&['continuous','family'].includes(name))this.paintForm();
 }
 click(event){
  const summary=event.target.closest('[data-diag-raw]>summary'),run=this.runs[this.tool];
  if(summary&&run){run.showRaw=!summary.parentElement.open;return;}
  const button=event.target.closest('button');if(!button||button.disabled)return;
  if(button.hasAttribute('data-diag-clear')){delete this.runs[this.tool];this.paint();return;}
  if(button.hasAttribute('data-diag-copy')){
   const text=this.runs[this.tool]?.lines.map(l=>l.text).join('\n')||'';
   navigator.clipboard?.writeText(text).then(()=>this.h.toast('Output copied.'),()=>this.h.toast('The browser blocked clipboard access.'));
  }
 }
 request(tool){
  const o=this.options[tool],l=this.limits(tool),destination=String(o.destination).trim();
  const int=(value,min,max,label)=>{const n=Number(value);if(!Number.isInteger(n)||n<min||n>max)throw new Error(`${label} must be a whole number from ${min} to ${max}.`);return n;};
  if(!validHost(destination))throw new Error('Enter an IP address or hostname to test.');
  if(/^[\d.]+$/.test(destination)&&o.family==='ipv6'||destination.includes(':')&&o.family==='ipv4')throw new Error(`That address is not ${o.family==='ipv6'?'IPv6':'IPv4'}. Change the IP family.`);
  const common={destination,family:o.family,interface:o.interface||''};
  if(tool==='ping')return {...common,count:o.continuous?l.count_max:int(o.count,1,l.count_max,'Count'),size:int(o.size,0,o.family==='ipv6'?Math.min(l.size_max,1452):l.size_max,'Packet size'),ttl:o.ttl===''||o.ttl===null?null:int(o.ttl,1,l.ttl_max,'TTL'),timeout:int(o.timeout,1,10,'Reply timeout')};
  return {...common,max_hops:int(o.max_hops,1,l.hops_max,'Max hops'),probes:int(o.probes,1,l.probes_max,'Probes per hop'),wait:int(o.wait,1,l.wait_max,'Probe timeout'),protocol:o.protocol,resolve:!!o.resolve};
 }
 async start(tool){
  if(this.running(tool))return;
  let payload;
  try{payload=this.request(tool);}
  catch(error){const element=this.host?.querySelector('[data-diag-error]');if(element){element.hidden=false;element.textContent=error.message;}this.host?.querySelector('[name=destination]')?.focus();return;}
  const controller=new AbortController();
  const run={tool,state:'running',options:payload,count:payload.count||0,controller,startedAt:Date.now(),lines:[],command:'',replies:[],seen:new Set(),maxSeq:-1,duplicates:0,hops:new Map(),names:new Map(),summary:null,showRaw:this.runs[tool]?.showRaw};
  this.runs[tool]=run;this.paint();
  try{
   const response=await apiFetch('/api/v1/diagnostics/'+tool,{method:'POST',body:JSON.stringify(payload),signal:controller.signal,headers:{Accept:'application/x-ndjson'}});
   if(!response.body)throw new Error('This browser cannot stream diagnostics.');
   const reader=response.body.pipeThrough(new TextDecoderStream()).getReader();let buffer='';
   for(;;){
    const {value,done}=await reader.read();if(done)break;
    buffer+=value;let index;
    while((index=buffer.indexOf('\n'))>=0){const line=buffer.slice(0,index).trim();buffer=buffer.slice(index+1);if(line)this.event(run,JSON.parse(line));}
   }
   if(run.state==='running'){run.state='error';run.message='The connection to the Titan ended before the test finished.';}
  }catch(error){
   if(controller.signal.aborted){if(run.state==='running')run.state='stopped';}
   else if(error instanceof SessionExpired){this.h.expire();return;}
   else if(run.state==='running'){run.state='error';run.message=error.status===429?'Too many tests are running on this Titan. Stop one and try again.':error.name==='TimeoutError'||error instanceof TypeError?'The connection to the Titan was interrupted.':error.message;}
  }finally{
   run.endedAt??=Date.now();
   if(this.runs[tool]===run&&this.tool===tool)this.paint();
  }
 }
 stop(tool){const run=this.runs[tool];if(!run||run.state!=='running')return;run.state='stopped';run.endedAt=Date.now();run.controller.abort();this.paint();}
 event(run,event){
  if(this.runs[run.tool]!==run||run.state!=='running'&&event.type!=='rdns')return;
  run.waiting=false;
  if(event.type==='start'){run.command=event.command||'';run.spawnedAt=Date.now();}
  else if(event.type==='line'){
   const text=String(event.text??'');run.lines.push({text,stream:event.stream});if(run.lines.length>MAX_LINES*2)run.lines.splice(0,run.lines.length-MAX_LINES);
   if(run.tool==='ping')parsePingLine(run,text);else parseTracerouteLine(run,text);
  }
  else if(event.type==='rdns')run.names.set(event.address,event.name||null);
  else if(event.type==='heartbeat')run.waiting=true;
  else if(event.type==='end'){
   run.endedAt=Date.now();run.exitCode=event.exit_code;
   run.state=event.reason==='stopped'?'stopped':event.reason==='completed'?'done':'error';
   if(run.state==='error')run.message=event.message||(event.reason==='timeout'?'The test reached its time limit on the Titan.':'The test could not finish.');
   run.ok=run.tool==='ping'?run.replies.length>0:run.reached||event.exit_code===0;
  }
  if(this.tool===run.tool)this.schedule();
 }
}
