import './align.css';
import * as E from './estimator.js';
import * as P from './predict.js';
import * as D from './diagnostics.js';
import * as S from './search.js';
import * as F from './feedback.js';
import {reduceMotion, reveal, setLiveText} from '../motion.js';

// Align screen. renderAlign() draws the current state as a string; update()
// ingests the newest snapshot and patches the mounted DOM in place. Everything
// moves on new modem readings only: between readings nothing changes but ages.
const STEPS=[['find','Find'],['peak','Peak'],['confirm','Confirm'],['record','Record']];
const METER={sinr:{label:'Quality',unit:'dB',min:-5,max:30,metric:'quality'},rsrp:{label:'Signal',unit:'dBm',min:-120,max:-70,metric:'rsrp'}};
const SIGMA_H={abs:6,ios:6,'ios-raw':8,sim:2,rel:2,manual:4.3};
const WORDS={excellent:'Excellent',good:'Good',marginal:'Fair'};
// Hold has no glyph: a lone dot in a box says nothing, the text carries it.
const ARROWS={left:'←',right:'→'};
const CAPTION={up:'♪ better',down:'♪ weaker',steady:'♪ steady'};
const VERDICT={worse:'Weaker',same:'About the same',unsure:'Not sure yet: add a reading','different-cell':'Different cell'};
const CONFLICT=new Set(['turn','try-side','passed','irregular','go-back']);
const CELL_BANNER_MS=10000,STRIP_N=40,POSE_MS=5000;
const finite=v=>typeof v==='number'&&Number.isFinite(v);
const clamp=(v,a,b)=>Math.max(a,Math.min(b,v));
const fx=(v,d=1)=>finite(v)?v.toFixed(d):'—';
const num=(v,d=1)=>finite(v)?v.toFixed(d).replace('-','−'):'—';
const signed=(v,d=1)=>{if(!finite(v))return '—';const a=Math.abs(v).toFixed(d);return (Number(a)===0?'±':v>0?'+':'−')+a;};
const pct=(v,min,max)=>finite(v)?clamp((v-min)/(max-min)*100,0,100):0;
const escText=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const mq=q=>typeof matchMedia==='function'&&!!matchMedia(q).matches;
const isDesktop=()=>mq('(min-width:1024px)');
const isLandscape=()=>mq('(orientation:landscape) and (max-height:520px)');
const hidden=()=>typeof document!=='undefined'&&!!document.hidden;
const safe=(f,fallback=null)=>{try{return f();}catch{return fallback;}};
const word=(key,g)=>g==='fail'?(key==='rsrp'?'Weak':'Poor'):WORDS[g]||'';
const mean=list=>{const v=list.filter(finite);return v.length?v.reduce((a,b)=>a+b,0)/v.length:null;};
const powerMean=E.powerMean||(list=>{const v=(list||[]).filter(finite);return v.length?10*Math.log10(v.reduce((a,x)=>a+10**(x/10),0)/v.length):null;});
const wrap180=S.wrap180||(x=>((x+540)%360)-180);
const gradeOf=(metric,v)=>finite(v)?safe(()=>D.grade(metric,v)):null;
const mbps=v=>!finite(v)?'—':v>=10?Math.round(v).toString():v.toFixed(1);
// Not in the spec: search.js may export bearingPoints; this mirrors spec 4.5.
const bearingPoints=S.bearingPoints||((session,{pci,R,poseSource})=>{
 const pts=[];
 for(const p of session.positions||[])if(p.heading&&finite(p.heading.deg)&&finite(p.signal?.mean)&&(pci==null||p.pci===pci))
  pts.push({heading:p.heading.deg,y:p.signal.mean,se:p.signal.se??0.5,sigmaH:SIGMA_H[p.heading.source]??6,relative:!!p.heading.relative});
 for(const r of session.sweep||[])if(finite(r.heading)&&finite(r.raw)&&(pci==null||r.pci===pci))
  pts.push({heading:r.heading,y:r.raw,se:Math.max(Math.sqrt(R??0),0.3),sigmaH:SIGMA_H[r.source||poseSource]??6,relative:!!r.relative});
 return pts;
});
const QUIET={
 audio:{supported:false,enabled:false,async enable(){return false;},disable(){},reading(){},click(){},chime(){},fault(){},staleTick(){},suspend(){},resume(){}},
 haptics:{supported:false,pulse(){}},
 compass:{active:false,async start(){return 'none';},stop(){},pose(){return null;},setLocation(){},setDeclinationOverride(){},onChange(){return ()=>{};}},
 wake:{supported:false,active:false,async request(){return false;},async release(){}}
};
const make=(C,key)=>{try{return C?new C():{...QUIET[key]};}catch{return {...QUIET[key]};}};

const COMPASS_MSG={abs:'Compass on. Press the phone flat against the back of the panel.',ios:'Compass on. Press the phone flat against the back of the panel.',rel:'Compass on (relative headings only).',
 denied:'Compass permission was denied.',none:'No compass found on this phone.',insecure:'Compass needs HTTPS.'};
let fallbackScreen;
export function renderAlign(ctx){return markup(ctx.screen||(fallbackScreen||=new AlignScreen({kind:'demo'})),ctx);}

export class AlignScreen {
 constructor({toast,kind}={}){
  this.toast=toast||(()=>{});this.kind=kind||'demo';
  this.prefs={sun:false,captions:false,useCompass:false,details:null};
  this.source=null;this.el=null;this._mounted=false;this._ctx=null;this._html=new WeakMap();
  this._init();
 }
 _init(){
  this.estimator=new E.SignalEstimator();this.session=new S.AlignSession();this.peak=new S.PeakTracker();this.bracket=new S.Bracket();this.diag=new D.Diagnostics();
  Object.assign(this,{step:'find',capture:null,capStatus:null,capFlash:null,lastSaved:null,cellChange:null,cells:new E.CellTracker(),cellPci:null,poses:[],findings:[],prediction:null,
   predDirty:true,carKey:'',dl256:false,dlPeak:null,passedOnce:false,goodSeen:false,caption:null,staleAt:0,guide:null,bearing:null,bearingNote:'',
   fitKey:'',snap:null,ev:null,d1:false,confirmId:null,pose:null,pingAt:0,attached:null,announceAt:0,revealNew:false});
 }
 get audio(){return this._audio||=make(F.AlignAudio,'audio');}
 get haptics(){return this._haptics||=make(F.Haptics,'haptics');}
 get compass(){return this._compass||=make(F.Compass,'compass');}
 get wake(){return this._wake||=make(F.WakeLockManager,'wake');}
 get mounted(){return this._mounted;}
 get capturing(){return !!this.capture;}
 render(ctx){return renderAlign({...ctx,screen:this});}

 mount(root,source){
  const el=root?.querySelector?.('[data-align]');if(!el)return;
  if(source!==this.source){this._unsub?.();this.source=source||null;this._unsub=safe(()=>source?.subscribe?.(()=>this.update()));}
  if(el!==this.el){this._unbind?.();this.el=el;this._unbind=this._bind(el);}
  this._timer??=setInterval(()=>this.update(),1000);
  this._mounted=true;this.update();
 }
 unmount(){
  if(!this._mounted&&!this.el)return;
  this._unbind?.();this._unsub?.();clearInterval(this._timer);
  this._unbind=this._unsub=this._timer=null;this.el=null;this.source=null;this._mounted=false;
  if(typeof document!=='undefined')document.documentElement?.classList?.remove?.('align-sun');
 }
 _bind(el){
  const click=event=>{const b=event.target.closest('[data-align-action]');if(b&&!b.disabled&&el.contains(b))this._action(b.dataset.alignAction,b);};
  const change=event=>{const t=event.target;
   if(t.matches('[data-align-field=declination]')){const v=t.value.trim()===''?null:Number(t.value);safe(()=>this.compass.setDeclinationOverride(finite(v)?v:null));}
   if(t.matches('[data-align-field=use-compass]'))this.prefs.useCompass=t.checked;};
  const toggle=event=>{if(event.target.matches?.('[data-align-details]'))this.prefs.details=event.target.open;};
  const key=event=>{
   if(!this._mounted||event.defaultPrevented||event.ctrlKey||event.metaKey||event.altKey||!isDesktop())return;
   const t=event.target;if(t?.closest?.('input,textarea,select,[contenteditable],dialog')||document.querySelector('dialog[open]'))return;
   const k=event.key.toLowerCase(),$=s=>this.el?.querySelector(s);
   const map={m:()=>{const b=$('[data-action=mark]');if(b&&!b.disabled)this.mark();},s:()=>$('[data-action=audio]')?.click(),f:()=>$('[data-action=focus]')?.click(),
    u:()=>this._action('undo'),n:()=>this._action('next'),r:()=>this._action('reset-peak')};
   if(map[k]){event.preventDefault();map[k]();}
  };
  el.addEventListener('click',click);el.addEventListener('change',change);el.addEventListener('toggle',toggle,true);
  if(typeof document!=='undefined')document.addEventListener('keydown',key);
  return ()=>{el.removeEventListener('click',click);el.removeEventListener('change',change);el.removeEventListener('toggle',toggle,true);if(typeof document!=='undefined')document.removeEventListener('keydown',key);};
 }

 async _action(name,button){
  const now=Date.now(),est=this._est();
  if(name==='step'){this.step=button?.dataset.step||this.step;}
  else if(name==='next'){const i=STEPS.findIndex(([id])=>id===this.step);if(i<STEPS.length-1)this.step=STEPS[i+1][0];}
  else if(name==='cancel'){if(this.capture)this.cancelCapture('user');else{safe(()=>this.bracket.cancel());if(this._lock()&&this._lock()!=='locked')this.session.lock=null;}}
  else if(name==='undo'){const r=safe(()=>this.session.undo());if(r){this.predDirty=true;this.fitKey='';if(this.confirmId===r.id)this.confirmId=null;this.toast(r.index!=null?`Position ${r.index} removed.`:'Last position removed.');}}
  else if(name==='reset-peak'){safe(()=>this.peak.reset());safe(()=>this.bracket.cancel());this.passedOnce=false;}
  else if(name==='bracket'){if(!this.peak.peak){this.toast('Find the peak first: sweep until a peak is confirmed.');return;}safe(()=>this.bracket.start(est,this.peak.peak));}
  else if(name==='lock'){if(!finite(est?.signal?.raw)){this.toast('Wait for a reading before the lock check.');return;}safe(()=>this.session.startLock(est));}
  else if(name==='start'){await this._start();}
  else if(name==='compass'){await this._toggleCompass();}
  else if(name==='sunlight')this.prefs.sun=!this.prefs.sun;
  else if(name==='captions')this.prefs.captions=!this.prefs.captions;
  else if(name==='export-json')this.exportJson();
  else if(name==='print'){if(typeof window!=='undefined')window.print();return;}
  this.guide=this._guidance(now);this._patch(now);
  // Below desktop the record card sits far down the page; bring it to the installer.
  if((name==='step'||name==='next')&&this.step==='record'&&!isDesktop())safe(()=>this.el?.querySelector('[data-align-record]')?.scrollIntoView({behavior:reduceMotion()?'auto':'smooth',block:'start'}));
 }
 async _start(){
  // All three start inside the tap: iOS only grants audio and motion during a user gesture.
  const settle=(f,fallback)=>Promise.resolve(safe(f,fallback)).catch(()=>fallback);
  const compass=this.prefs.useCompass&&this.kind==='device'?settle(()=>this.compass.start(),'none'):null;
  const audio=settle(()=>this.audio.enable(),false),wake=settle(()=>this.wake.request(),false);
  const ok=await audio;await wake;
  // One toast: a second one in the same task would replace the compass result before it is read.
  const cm=compass?COMPASS_MSG[await compass]:'';
  this.toast([ok?'Sound is on. One ping per reading: rising means better.':'Audio is unavailable here. Watch the number and the arrows.',cm].filter(Boolean).join(' '));
 }
 async _toggleCompass(){
  if(this.compass.active){safe(()=>this.compass.stop());this.toast('Compass off.');return;}
  this._compassResult(await Promise.resolve(safe(()=>this.compass.start(),'none')).catch(()=>'none'));
 }
 _compassResult(r){
  const msg=COMPASS_MSG[r];
  if(msg)this.toast(msg);
 }

 mark(){
  const snap=this.snap||safe(()=>this.source?.snapshot?.()),now=Date.now();
  if(this.capture||!this._markEnabled(snap,now))return;
  this.capture=new S.Capture({t0:now,pci:snap.cell?.pci??null,eci:snap.cell?.eci??null,need:S.CAPTURE?.need??3});
  this.capStatus={status:'collecting',n:0,nQuality:0,need:S.CAPTURE?.need??3,at:now,restartedAt:null};this.capFlash=null;
  this._announce('Hold still.',true);
  this.guide=this._guidance(now);this._patch(now);
 }
 cancelCapture(reason){
  if(!this.capture)return;
  this.capture=null;this.capStatus=null;
  const msgs={user:'Position capture canceled.',paused:'Position capture canceled. Readings are paused.',hidden:'Position capture canceled. Keep this page open while marking.',cell:null,
   stale:'Position capture canceled. Signal updates stopped.',expired:'Position capture canceled. Sign in again to keep marking.',restart:'Position capture canceled. The connection is restarting.',scenario:'Position capture canceled.'};
  const text=reason in msgs?msgs[reason]:'Position capture canceled. Fresh readings from one cell are required.';
  if(text)this.toast(text);
  if(this.el?.isConnected){const now=Date.now();this.guide=this._guidance(now);this._patch(now);}
 }
 clearPositions(){
  this.cancelCapture('user');safe(()=>this.session.clear());this.lastSaved=null;this.confirmId=null;this.predDirty=true;this.fitKey='';
  this._patch(Date.now());
 }
 exportCsv(){
  const rows=[...(this.session.archived||[]).flatMap(g=>(g.positions||[]).map(p=>[p,'archived'])),...(this.session.positions||[]).map(p=>[p,'current'])];
  if(!rows.length){this.toast('Mark a position before exporting.');return;}
  const verdicts=safe(()=>this.session.verdicts(),new Map()),best=safe(()=>this.session.best());
  const src=this.kind==='demo'?'SIMULATED':'LIVE',c=v=>v==null?'':String(v).replace(/[",\n]/g,' ');
  const head='position,pci,sinr_db,rsrp_dbm,source,quality_source,signal_se_db,quality_se_db,readings,quality_readings,rx1_dbm,rx2_dbm,best_rx_dbm,imbalance_db,rsrq_db,margin_db,heading_deg,heading_relative,low_confidence,unsteady,quality_held,verdict,cell_state,earfcn,eci,time';
  const lines=rows.map(([p,state],i)=>[p.index??i+1,p.pci,fx(p.quality?.mean,2).replace('—',''),fx(p.signal?.mean,2).replace('—',''),src,p.quality?.source??'',fx(p.signal?.se,2).replace('—',''),fx(p.quality?.se,2).replace('—',''),
   p.n??'',p.nQuality??'',fx(p.rx?.[0]).replace('—',''),fx(p.rx?.[1]).replace('—',''),fx(p.best).replace('—',''),fx(p.imbalance).replace('—',''),fx(p.rsrq).replace('—',''),fx(p.margin).replace('—',''),
   p.heading?fx(p.heading.deg).replace('—',''):'',p.heading?p.heading.relative?1:0:'',p.flags?.lowConfidence?1:0,p.flags?.unsteady?1:0,p.flags?.qualityHeld?1:0,
   state==='current'?(best?.position?.id===p.id?'best':verdicts.get?.(p.id)?.verdict??''):'',state,p.earfcn??'',p.eci??'',finite(p.t)?new Date(p.t).toISOString():''].map(c).join(','));
  download(`titan-${this.kind==='demo'?'demo-':''}alignment.csv`,head+'\n'+lines.join('\n'),'text/csv');
  this.toast(this.kind==='demo'?'Demo download prepared.':'Alignment CSV downloaded.');
 }
 exportJson(){
  const now=Date.now(),est=this._est();
  const data={source:this.kind==='demo'?'SIMULATED':'LIVE',exported:new Date(now).toISOString(),step:this.step,cell:this.snap?.cell??null,
   session:safe(()=>typeof this.session.toJSON==='function'?this.session.toJSON():this.session),readings:est?.readings??[],cadence:est?.cadence??null,
   peak:this.peak.peak??null,findings:this.findings,acceptance:safe(()=>D.acceptance(this._dctx(now))),prediction:this.prediction};
  download(`titan-${this.kind==='demo'?'demo-':''}alignment-session.json`,JSON.stringify(data,null,2),'application/json');
  this.toast('Session JSON downloaded.');
 }
 async toggleAudio(){
  if(this.audio.enabled){safe(()=>this.audio.disable());this.toast('Sound off.');}
  else{const ok=await Promise.resolve(safe(()=>this.audio.enable(),false)).catch(()=>false);
   this.toast(ok?'One ping per reading. Rising means better, a chime marks a new peak.':'Audio is unavailable in this browser. Visual readings remain available.');}
  this._patch(Date.now());
 }
 async toggleWake(){
  if(this.wake.active){await Promise.resolve(safe(()=>this.wake.release())).catch(()=>{});}
  else if(!this.wake.supported)this.toast('Keep awake is unavailable here. Adjust your phone’s screen timeout.');
  else{const ok=await Promise.resolve(safe(()=>this.wake.request(),false)).catch(()=>false);this.toast(ok?'Screen will stay awake while this page is visible.':'Your browser could not keep the screen awake.');}
  this._patch(Date.now());
 }
 silence(){if(this._audio?.enabled){safe(()=>this._audio.suspend());this._suspended=true;}}
 leave(){
  this.cancelCapture('hidden');
  if(this._audio?.enabled)safe(()=>this._audio.disable());
  // Always release: a pending request or a lock dropped while hidden is not active, yet still wanted.
  if(this._wake)Promise.resolve(safe(()=>this._wake.release())).catch(()=>{});
  if(this._compass?.active)safe(()=>this._compass.stop());
  safe(()=>this.bracket.cancel());this._suspended=false;
 }
 reset(){
  this.leave();this._init();this.prefs={sun:false,captions:false,useCompass:false,details:null};
  if(this.el?.isConnected)this._patch(Date.now());
 }

 update(){
  const now=Date.now(),snap=safe(()=>this.source?.snapshot?.())??null;
  this.snap=snap;
  const ev=safe(()=>this.estimator.ingest(snap,now));this.ev=ev;this._ec=null;
  const est=this._est();
  this._cell(snap,now);
  if(snap&&!snap.attached&&this.attached){safe(()=>this.peak.reset());safe(()=>this.bracket.cancel());this.passedOnce=false;this._fault();}
  if(snap)this.attached=!!snap.attached;
  const pose=this.pose=this._pose(snap);
  this.poses=this.poses.filter(p=>now-p.at<=POSE_MS);if(pose)this.poses.push({at:now,pose});
  if(this._suspended&&!hidden()&&this._audio?.enabled){safe(()=>this._audio.resume());this._suspended=false;}
  if(ev?.signal==='new')this._reading(est,now);
  else if(ev?.signal==='revised')this._revise(est);
  if(this.capture)this._captureStep(est,snap,pose,now);
  if(snap){
   const dl=snap.throughput?.dlBps;if(finite(dl))this.dlPeak=Math.max(this.dlPeak??0,dl);
   if(snap.radio?.dlModulation==='256QAM'||(snap.carriers||[]).some(c=>c.dlModulation==='256QAM'))this.dl256=true;
   if(snap.gps?.fix&&finite(snap.gps.latitude)&&this._compass?.active)safe(()=>this._compass.setLocation(snap.gps.latitude,snap.gps.longitude,snap.gps.altitudeM));
  }
  const carKey=JSON.stringify((snap?.carriers||[]).map(c=>[c.role,c.pci,c.earfcn,c.bandwidthMhz,c.active]));
  if(ev?.quality==='new'||carKey!==this.carKey||this.predDirty){this.carKey=carKey;this.predDirty=false;this.prediction=this._predict(est?.quality?.est,est?.quality?.sd);}
  this._fit(est);
  this.findings=safe(()=>this.diag.update(this._dctx(now),{newEvidence:ev?.signal==='new'||ev?.quality==='new'}),[])||[];
  const d1=this.findings.some(f=>f.id==='D1');if(d1&&!this.d1){this._fault();this._announce('No spectrum grant.',true);}this.d1=d1;
  this.guide=this._guidance(now);
  if(this.guide?.key==='good-enough')this.goodSeen=true;
  // Never assert a lock-down the hint or the bearing fit disagrees with.
  if(this._conflict()||!(this.session.positions||[]).length)this.findings=this.findings.filter(f=>f.id!=='D13');
  const state=this._state(now);
  if((state==='old'||state==='none')&&snap&&!snap.paused&&this._audio?.enabled&&!hidden()&&now-this.staleAt>=5000){this.staleAt=now;safe(()=>this._audio.staleTick());this.caption={text:'♪ waiting',t:now};}
  this._patch(now);
 }
 // stateAt() ages freshness to now between polls; cached briefly because one patch asks many times.
 _est(){const n=Date.now(),c=this._ec;if(c&&n-c.n<40&&c.v)return c.v;const v=safe(()=>this.estimator.stateAt?this.estimator.stateAt(n):this.estimator.state);this._ec={n,v};return v;}
 _lock(){return this.session.lock?.state??null;}
 _pose(snap){
  if(this.source?.pose)return safe(()=>this.source.pose());
  return this._compass?.active?safe(()=>this._compass.pose()):null;
 }
 _cell(snap,now){
  // Stale or detached data cannot announce a new sector; it is judged once readings are fresh again.
  if(!snap?.attached||snap.stale||!snap.connected||snap.cell?.pci==null)return;
  const from=this.cellPci;this.cellPci=snap.cell.pci;
  if(!this.cells.offer(snap.cell.pci,snap.cell.eci,now))return;
  if(this.capture){this.capture=null;this.capStatus=null;}
  safe(()=>this.session.onCellChange(from,snap.cell.pci));safe(()=>this.peak.reset());safe(()=>this.bracket.cancel());safe(()=>this.diag.reset());
  Object.assign(this,{passedOnce:false,goodSeen:false,confirmId:null,lastSaved:null,predDirty:true,fitKey:'',bearing:null,cellChange:{from,to:snap.cell.pci,t:now}});
  this._fault();this._announce(`Now on PCI ${snap.cell.pci}. That is a different sector.`,true);
 }
 _fault(){if(!this._audio?.enabled)return;safe(()=>this._audio.fault());safe(()=>this.haptics.pulse('fault'));this.caption={text:'♪ problem',t:Date.now()};}
 // The heading when the reading was measured, not when it arrived: turning while it travels would bias the fit.
 _poseAt(t){const r=this.poses;if(!r.length||!finite(t))return this.pose;let hit=r[0];for(const p of r)if(p.at<=t+250)hit=p;return hit.pose;}
 _revise(est){
  const s=est?.signal;if(!s||!finite(s.raw))return;
  const pose=this._poseAt(s.readingT??s.t);
  safe(()=>this.session.logSweep(est,null,this.snap?.cell?.pci??null));safe(()=>this.peak.offer(est,pose));
 }
 _reading(est,now){
  const s=est?.signal;if(!s||!finite(s.raw))return;
  const pci=this.snap?.cell?.pci??null,pose=this._poseAt(s.readingT??s.t);
  safe(()=>this.session.logSweep(est,pose,pci));
  const newPeak=!!safe(()=>this.peak.offer(est,pose)?.newPeak);
  if(safe(()=>this.peak.passed(est)))this.passedOnce=true;
  const bs=safe(()=>this.bracket.state);
  if(bs&&bs!=='idle'&&bs!=='done'){const next=safe(()=>this.bracket.offer(est,this.peak.peak));if(next==='left-edge'&&bs!=='left-edge'&&this._audio?.enabled)safe(()=>this.haptics.pulse('mark'));}
  const lk=this._lock();
  if(lk&&lk!=='locked'){
   const r=safe(()=>this.session.offerLock(est));
   if(r==='dropped'&&lk!=='dropped')this._fault();
   if(r==='locked')this._announce('Locked. Record the install.',true);
  }
  const peak=this.peak.peak,atPeak=!!(peak&&safe(()=>this.peak.atPeak(est)));
  const hz=safe(()=>this.step==='find'||!peak?F.pitchAbsolute(s.raw):F.pitchZoom(peak.value-s.raw,s.deadband));
  if(this._audio?.enabled&&!hidden()){
   safe(()=>this._audio.reading({hz,trend:s.trend??null,newPeak,atPeak}));
   safe(()=>this.haptics.pulse(newPeak?'peak':s.trend==='up'?'better':s.trend==='down'?'worse':'steady'));
  }
  this.caption={text:newPeak?'♪ new peak':atPeak?'♪ at peak':CAPTION[s.trend]||'♪ steady',t:now};
  this.pingAt=now;
  if(newPeak)this._announce(`New peak, ${num(peak.value)} dBm.`);
 }
 _captureStep(est,snap,pose,now){
  const st=safe(()=>this.capture.offer(est,snap,pose,now),{status:'failed',n:0,need:3,reason:'error'});
  const prevN=this.capStatus?.n??0;this.capStatus=st;
  if(st.status==='collecting'&&st.n>prevN&&this._audio?.enabled){safe(()=>this._audio.click());safe(()=>this.haptics.pulse('click'));}
  if(st.status==='done'){const rec=safe(()=>this.capture.result(this.session));this.capture=null;this.capStatus=null;if(rec)this._save(rec,now);}
  else if(st.status==='failed'){this.capture=null;this.capStatus=null;this.capFlash={...st,at:st.at??now};this._fault();this.toast('Signal not updating. Check the link.');}
  else if(st.status==='aborted')this.cancelCapture(st.reason);
 }
 _save(rec,now){
  const m=safe(()=>D.derive(this._dctx(now))?.margin);
  if(rec.margin==null)rec.margin=finite(m?.db)?m.db:null;
  if(!rec.predict&&finite(rec.quality?.mean)){const p=this._predict(rec.quality.mean,rec.quality.se);if(p)rec.predict={dlMbps:p.dlMbps,dlLo:p.dlLo,dlHi:p.dlHi,potential:p.potential,modulation:p.dlModulation??null};}
  const saved=safe(()=>this.session.add(rec))||rec;
  const index=saved.index??(this.session.positions||[]).indexOf(saved)+1;
  if(this.step==='confirm'||this.step==='record')this.confirmId=saved.id;
  this.lastSaved={index,n:index,t:now};this.cellChange=null;this.predDirty=true;this.fitKey='';this.revealNew=true;
  if(this._audio?.enabled){safe(()=>this._audio.chime());safe(()=>this.haptics.pulse('mark'));}
  this.caption={text:'♪ saved',t:now};
  this._announce(`Position ${index} saved.`,true);
 }
 _announce(text,force=false){
  const now=Date.now();if(!force&&now-this.announceAt<5000)return;
  this.announceAt=now;const el=this.el?.querySelector('[data-align-announce]');if(el)el.textContent=text;
 }
 _predict(sinr,sd){
  const snap=this.snap;if(!snap||!finite(sinr)||!P.predict)return null;
  const cars=(snap.carriers||[]).filter(c=>c.active!==false),pcc=cars.find(c=>c.role==='pcc');
  const cqiFresh=(snap.throughput?.dlBps??0)>=1e6;
  const carriers=[{role:'pcc',bwMhz:pcc?.bandwidthMhz||20,sinr,sinrSd:finite(sd)?sd:1,cqi:snap.radio?.cqi??null,ri:snap.radio?.ri??null,cqiFresh}];
  for(const c of cars){if(c.role!=='scc')continue;const ch=powerMean((c.cinrChains||[]).filter(finite)),v=finite(ch)?ch:c.sinr;if(finite(v))carriers.push({role:'scc',bwMhz:c.bandwidthMhz||20,sinr:v,sinrSd:1});}
  return safe(()=>P.predict({carriers,input:this._est()?.quality?.source==='sinr'?'sinr':'cinr',caps:{dl256:this.dl256,maxLayers:2,catBitsPerTti:P.DEFAULTS?.catBitsPerTti??452256},
   tdd:P.DEFAULTS?.tdd??{sa:2,ssp:7},ulMcsObserved:(snap.throughput?.ulBps??0)>=1e6?snap.radio?.ulMcs??null:null,txPowerDbm:snap.radio?.txPowerDbm??null}));
 }
 _fit(est){
  const pci=this.snap?.cell?.pci??null,sweep=this.session.sweep||[],pos=this.session.positions||[];
  const key=`${pci}/${sweep.length}/${sweep.at(-1)?.reading}/${pos.length}`;
  if(key===this.fitKey)return;this.fitKey=key;
  const pts=safe(()=>bearingPoints(this.session,{pci,R:est?.signal?.R??0.25,poseSource:this.pose?.source}),[])||[];
  const sig=pts.length>=3?safe(()=>S.fitBearing(pts,{})):null;
  const qp=pos.filter(p=>p.heading&&finite(p.heading.deg)&&finite(p.quality?.mean)&&p.pci===pci)
   .map(p=>({heading:p.heading.deg,y:p.quality.mean,se:p.quality.se??1,sigmaH:SIGMA_H[p.heading.source]??6,relative:!!p.heading.relative}));
  const q=qp.length>=3?safe(()=>S.fitBearing(qp,{})):null;
  this.bearingNote='';this.bearing=sig;
  if(sig?.valid&&q?.valid){
   const d=wrap180(q.theta0-sig.theta0);
   if(Math.abs(d)<sig.theta3/2)this.bearing=q;
   else this.bearingNote=`Interference is stronger to the ${d>0?'left':'right'}.`;
  }
  this.points=pts;
 }
 _dctx(now){
  const est=this._est(),pos=this.session.positions||[],best=safe(()=>this.session.best());
  const final=(this.confirmId&&pos.find(p=>p.id===this.confirmId))||best?.position||null;
  const c=this.capture,capture=c?{t0:c.t0+(S.CAPTURE?.settleMs??0),signals:c.got.map(r=>r.signal),quality:c.gotQ.map(q=>q.v)}:null;
  return {now,estimate:est,snapshot:this.snap,positions:pos,peak:this.peak.peak??null,capturing:!!c,capture,bearing:this.bearing,dlPeakBps:this.dlPeak,final};
 }
 _guidance(now){
  const est=this._est(),flash=this.capFlash&&now-this.capFlash.at<8000?this.capFlash:null;
  const g=safe(()=>S.guidance({step:this.step,estimate:est,snapshot:this.snap,capture:this.capStatus||flash,captureLabel:this.capture?safe(()=>this.capture.label()):null,
   peak:this.peak,bracket:this.bracket,lock:this.session.lock??null,session:this.session,bearing:this.bearing,pose:this.pose,
   best:safe(()=>this.session.best()),lastSaved:this.lastSaved,cellChange:this.cellChange,now}));
  if(!g)return {key:'none',text:this.snap?'Turn about 15°, then hold until the ping.':'Connecting to Titan…',detail:'',tone:'quiet',arrow:'none'};
  // The grant blocker owns the verdict: never say "lock it down" while the radio cannot send.
  if(this.d1&&g.key==='good-enough')return {...g,text:'Good aim, but there is no spectrum grant yet.',tone:'attention'};
  if(this.bearingNote&&/^(good-enough|turn|irregular|try-side)$/.test(g.key))return {...g,detail:[g.detail,this.bearingNote].filter(Boolean).join(' · ')};
  return g;
 }
 _state(now){
  const snap=this.snap,s=this._est()?.signal;
  if(!snap)return 'connecting';
  if(snap.paused)return 'paused';
  if(!snap.attached||snap.stale||!snap.connected)return 'none';
  if(!s||!finite(s.raw))return 'first';
  return this._est()?.freshness||'none';
 }
 _pWithin(){
  const b=this.bearing,p=this.pose;
  if(!b?.valid||!b.fitOk||!p||!finite(p.heading)||!!p.relative!==!!b.relative)return null;
  return safe(()=>b.pWithinAt(p.heading));
 }
 _conflict(){const w=this._pWithin();return CONFLICT.has(this.guide?.key)||(finite(w)&&w<0.9);}
 _markEnabled(snap,now){
  if(!snap||!snap.connected||snap.paused||snap.stale)return false;
  const t=snap.signal?.t??this._est()?.signal?.t;
  return !(snap.signal&&finite(t)&&now-t>30000);
 }
 _suggest(now){
  const pos=this.session.positions||[];
  if(this.step==='find')return !!(this.peak.peak&&this.passedOnce)||!!this.bearing?.valid;
  if(this.step==='peak')return this.goodSeen||pos.length>=3;
  if(this.step==='confirm')return this._lock()==='locked';
  return false;
 }

 // View model shared by markup() and _patch().
 _view(now=Date.now()){
  const snap=this.snap,est=this._est(),s=est?.signal||{},q=est?.quality||{},state=this._state(now);
  const has=['live','waiting','old','paused'].includes(state);
  const sigOk=has&&finite(s.raw),qOk=has&&finite(q.raw);
  const headline=this.step==='confirm'?'quality':'signal';
  const H=headline==='quality'?{v:q.raw,ok:qOk,unit:'dB',label:'Quality',trend:q.trend,delta:q.delta}:{v:s.raw,ok:sigOk,unit:'dBm',label:'Signal',trend:s.trend,delta:s.delta};
  const showTrend=H.ok&&state!=='old'&&state!=='paused'&&finite(H.delta)&&H.trend;
  const best=safe(()=>this.session.best()),bestPos=best?.position;
  const ageS=finite(s.t)?Math.max(0,Math.floor((now-s.t)/1000)):null;
  const eta=est?.cadence?.signalEta,expected=est?.cadence?.signalMs||2500;
  return {now,snap,est,s,q,state,sigOk,qOk,headline,H,showTrend,best,bestPos,ageS,eta,expected,paused:!!snap?.paused,
   tween:Math.round(clamp(expected/4,150,600))};
 }
}

// ---- markup -----------------------------------------------------------------
function markup(screen,ctx){
 screen._ctx=ctx;
 const esc=ctx.esc||escText,icon=ctx.icon||(()=>''),now=Date.now(),v=screen._view(now),cfg=ctx.config||{};
 if(screen.guide===null)screen.guide=screen._guidance(now);
 const focusBtn=ctx.button?ctx.button(ctx.focus?'Exit focus':'Focus mode','focus',ctx.focus?'Minimize':'Maximize'):'';
 const head=ctx.head?ctx.head('','Antenna alignment','Find the strongest, cleanest signal, then lock it down.',focusBtn):'<div class="page-head"><div><h1>Antenna alignment</h1></div></div>';
 const lock=cfg.pciMode&&cfg.pciMode!=='Automatic'?`<div class="lock-notice"><span>Cell selection: ${esc(cfg.pciMode)}${cfg.pciMode==='Preferred list'?' / PCI '+(cfg.pciTargets||[]).map(t=>esc(t.pci)).join(', '):''}</span>${ctx.button?ctx.button('Edit PCI lock','open-lock','Settings2','btn-small'):''}</div>`:'';
 const big=bigVM(screen,v),pk=peakVM(screen,v),fr=freshVM(screen,v),mk=markVM(screen,v),ac=actionsVM(screen,v),g=screen.guide||{},banner=bannerHTML(screen,v,esc);
 const btn=(text,action,ic,cls='')=>ctx.button?ctx.button(text,action,ic,cls):`<button type="button" class="btn ${cls}" data-action="${action}">${text}</button>`;
 const ab=(action,label,ic,attrs='')=>`<button type="button" class="btn" data-align-action="${action}" ${attrs}>${ic?icon(ic):''}${label}</button>`;
 const audioOn=!!screen._audio?.enabled,wakeOn=!!screen._wake?.active,compassOn=!!screen._compass?.active;
 const kb=isDesktop()?k=>` title="Shortcut: ${k}"`:()=>'';
 const caps=screen.kind==='device'&&safe(()=>F.Compass?.capabilities?.())?.secure;
 const details=screen.prefs.details??isDesktop();
 return `<div class="align${screen.prefs.sun?' is-sun':''}" data-align data-step="${screen.step}" data-freshness-state="${v.state}" style="--align-tween:${v.tween}ms">
 ${head}${lock}
 <div class="align-grid">
  <section class="card align-live" aria-label="Live signal">
   <div class="align-banner" data-align-banner role="alert"${banner?'':' hidden'}>${banner}</div>
   <nav class="align-steps" data-align-steps aria-label="Alignment steps">${STEPS.map(([id,label],i)=>`<button type="button" data-align-action="step" data-step="${id}"${screen.step===id?' aria-current="step"':''}><b>${i+1}</b>${label}</button>`).join('')}</nav>
   <div class="align-eyebrow-row"><span class="align-eyebrow" data-align-eyebrow>${big.eyebrow}</span><span class="align-cell" data-align-cell>PCI <strong data-live="pci">${esc(cellPci(v))}</strong><span data-align-enb>${esc(enbText(v))}</span></span></div>
   <div class="align-big-row"><span class="align-big" data-align-big>${big.text}</span><span class="align-trend" data-align-trend data-dir="${big.dir}"${big.trend?'':' hidden'}>${big.trend}</span><span class="align-caption" data-align-caption hidden></span></div>
   <div class="align-peak"><div class="align-peakbar" data-align-peakbar aria-hidden="true"><i class="align-peak-fill" style="width:${pk.fill.toFixed(1)}%"></i><i class="align-peak-recent" style="left:${pk.recent.toFixed(1)}%"${pk.showRecent?'':' hidden'}></i><i class="align-peak-session" style="left:${pk.session.toFixed(1)}%"${pk.showSession?'':' hidden'}></i></div><div class="align-peakline-row"><p class="align-peakline" data-align-peakline>${pk.line}</p><span class="align-heading" data-align-heading${fr.heading?'':' hidden'}>${fr.heading}</span></div></div>
   <div class="align-meters">${meterHTML(screen,v,'sinr')}${meterHTML(screen,v,'rsrp')}</div>
   <div class="align-fresh" data-align-fresh><svg class="align-ring" viewBox="0 0 18 18" aria-hidden="true"><circle class="align-ring-track" cx="9" cy="9" r="7"/><circle class="align-ring-age" cx="9" cy="9" r="7" stroke-dashoffset="${fr.offset.toFixed(1)}"/></svg><span class="align-fresh-text" data-align-fresh-text>${fr.text}</span><span class="align-collector" data-freshness>${fr.collector}</span></div>
   <figure class="align-strip"><svg data-align-strip viewBox="0 0 400 56" preserveAspectRatio="none" role="img" aria-label="Signal per reading">${stripSVG(screen,v)}</svg><figcaption><span>One bar per reading · best outlined</span><span data-align-strip-n>${stripCount(v)}</span></figcaption></figure>
   <div class="align-dock">
   <div class="align-guide">
    <div class="align-cue" data-hint data-tone="${g.tone||'quiet'}" role="status">${hintHTML(g,esc)}</div>
    <div class="align-start" data-align-start${startVisible(screen)?'':' hidden'}><button type="button" class="btn" data-align-action="start">${icon('Play')}Start</button><span>Turns on sound and keeps the screen awake.</span>${caps?`<label><input type="checkbox" data-align-field="use-compass"${screen.prefs.useCompass?' checked':''}>Use phone compass</label>`:''}</div>
   </div>
   <div class="align-actions">
    <button type="button" class="btn btn-primary align-mark" data-action="mark"${mk.disabled?' disabled':''}${mk.busy?' aria-busy="true"':''} style="--cap:${mk.progress}"${kb('M')}><span class="align-mark-icon" data-mark-icon>${icon(mk.busy?'Clock3':'Plus')}</span><span data-mark-label>${esc(mk.label)}</span></button>
    <div class="align-row">
     ${ab('undo','Undo','Undo2',`${ac.undo?'':'disabled'}${kb('U')}`)}
     ${ab('cancel','Cancel','X',ac.cancel?'':'hidden')}
     ${ab('bracket','Find edges','',ac.bracket?'':'hidden')}
     ${ab('lock','Start lock check','Lock',ac.lock?'':'hidden')}
     <button type="button" class="btn align-next${ac.suggest?' is-suggested':''}" data-align-action="next"${ac.next?'':' hidden'}${kb('N')}>${esc(ac.nextText)}</button>
    </div>
   </div>
   </div>
   <div class="align-controls" data-align-controls>
    ${btn(audioOn?'Sound on':'Sound off','audio',audioOn?'Volume2':'VolumeX')}
    ${btn(v.paused?'Resume':'Pause','pause',v.paused?'Play':'Pause')}
    ${btn(wakeOn?'Screen awake':'Keep awake','wake','Sun')}
    ${ab('compass','Compass','Compass',`aria-pressed="${compassOn}"${screen.kind==='demo'||screen.source?.pose?' hidden':''}`)}
    ${ab('sunlight','Sunlight','Eye',`aria-pressed="${screen.prefs.sun}"`)}
    ${ab('captions','Captions','Info',`aria-pressed="${screen.prefs.captions}"`)}
    ${ab('reset-peak','Reset peak','RotateCcw',kb('R'))}
   </div>
  </section>
  <aside class="align-side">
   <section class="card card-pad align-positions" aria-label="Positions">
    <div class="card-head"><h2>Positions</h2><span class="align-best-sum" data-align-best-sum>${bestSum(v)}</span></div>
    <p class="align-help">Each mark takes three fresh readings and one quality reading. Hold still while it records.</p>
    <div id="positions">${positionsHTML(screen,esc,icon)}</div>
    <div class="align-pos-actions">${btn('Export','export','Download','btn-small')}${btn('Clear','clear-positions','RotateCcw','btn-small')}</div>
   </section>
   <section class="card card-pad align-findings" data-align-findings-card aria-label="Findings"${findingsHTML(screen,esc)?'':' hidden'}><div class="card-head"><h2>Findings</h2></div><div data-align-findings>${findingsHTML(screen,esc)}</div></section>
   <section class="card card-pad align-record" data-align-record aria-label="Install record"${screen.step==='record'?'':' hidden'}>${recordHTML(screen,v,esc,icon)}</section>
  </aside>
  <section class="card card-pad align-evidence" aria-label="Evidence">
   <div class="card-head"><h2>Evidence</h2><span class="muted text-xs" data-align-source>${esc(sourceText(screen,v))}</span></div>
   <figure class="align-bearing" data-align-bearing-box${bearingVisible(screen)?'':' hidden'}><svg data-align-bearing viewBox="0 0 400 100" role="img" aria-label="Signal by heading">${bearingSVG(screen,v)}</svg><figcaption data-align-bearing-note>${esc(bearingCaption(screen))}</figcaption></figure>
   <div class="align-predict" data-align-predict>${predictHTML(screen,v)}</div>
   <details class="align-details" data-align-details${details?' open':''}><summary>Details</summary>
    <dl class="align-dl">${DETAILS.map(([k,label])=>`<div><dt>${label}</dt><dd${k.startsWith('live:')?'':` data-align-d="${k}"`}>${k==='live:chains'?`<span data-live="chains">${esc(chainsText(v))}</span> dBm`:k==='live:rsrq'?`<span data-live="rsrq">${esc(fx(v.est?.rsrq?.raw))}</span> dB`:esc(detailText(screen,v,k))}</dd></div>`).join('')}</dl>
    <div class="align-carriers" data-align-d="carriers">${carriersHTML(v,esc)}</div>
    <label class="align-decl">Declination override <input data-align-field="declination" type="number" step="0.1" placeholder="auto" inputmode="decimal"> °</label>
   </details>
  </section>
 </div>
 <div class="align-sr" data-align-announce aria-live="polite"></div>
</div>`;
}

// ---- regions ----------------------------------------------------------------
const cellPci=v=>v.snap?.cell?.pci??'—';
const enbText=v=>{const c=v.snap?.cell;return c?.enbId!=null?` · eNB ${c.enbId}${c.cellId!=null?'-'+c.cellId:''}`:'';};
// The headline follows the basis that picked the best position, so the numbers agree with the verdicts.
const bestSum=v=>v.best?.basis==='signal'&&finite(v.bestPos?.signal?.mean)?`Best signal <strong data-live="best">${num(v.bestPos.signal.mean)}</strong> dBm`
 :`Best quality <strong data-live="best">${fx(v.bestPos?.quality?.mean)}</strong> dB`;
const verdictText=(c,basis)=>{if(!c)return '';const m=basis==='quality'?'quality':'signal',d=finite(c.delta)?` (${signed(c.delta)} dB)`:'';
 return c.verdict==='better'?`Better ${m} (${Math.round((c.pBetter??0)*100)}%)`:c.verdict==='worse'?`Weaker ${m}${d}`:c.verdict==='same'?`About the same ${m}`:VERDICT[c.verdict]||'';};
const chainsText=v=>{const c=v.sigOk||v.state==='paused'?(v.s.chains||[]):[];return c.length?c.slice(0,2).map(x=>fx(x)).join(' / '):'—';};
const stripCount=v=>{const n=v.est?.signal?.n;return finite(n)&&n>0?`${n} reading${n===1?'':'s'}`:'';};
const startVisible=s=>!s._audio?.enabled&&s.step==='find';
const sourceText=(s,v)=>{const src=v.snap?.signal?.source;return src==='legacy'?'Approximate reading times':src==='sim'||s.kind==='demo'?'Simulated readings':src==='watch'?'Modem readings':'';};

function bigVM(screen,v){
 const {H,state}=v,eyebrow=`${H.label}<small>${H.unit}</small>`;
 const text=H.ok?num(H.v):state==='connecting'?'…':'—';
 const dir=v.showTrend?H.trend:'none';
 const arrow=dir==='up'?'▲':dir==='down'?'▼':'≈';
 return {eyebrow,text,dir,trend:v.showTrend?`${arrow} ${signed(H.delta)}`:''};
}
function peakVM(screen,v){
 const {s,state}=v,M=METER.rsrp,peak=screen.peak.peak,recent=safe(()=>screen.peak.recent(v.now));
 const ok=v.sigOk;
 let line;
 if(state==='connecting')line='Connecting to Titan…';
 else if(state==='paused')line='Readings paused';
 else if(!ok)line=state==='first'?"Waiting for the modem's first reading.":'No signal reading';
 else if(!peak)line=`No peak yet · <strong>${word('rsrp',gradeOf('rsrp',s.raw))||'—'}</strong>`;
 else{const below=peak.value-s.raw,db=Math.max(0.5,s.deadband||0.5);
  const at=below<=db?(screen._conflict()?'<strong>Best so far</strong>':'<strong>At the peak</strong>'):`<strong>${Math.max(0,below).toFixed(1)} dB</strong> below peak`;
  line=`${at} · ${word('rsrp',gradeOf('rsrp',s.raw))||'—'}`;}
 return {fill:ok?pct(s.raw,M.min,M.max):0,session:pct(peak?.value,M.min,M.max),recent:pct(recent,M.min,M.max),showSession:!!peak&&finite(peak.value),showRecent:finite(recent)&&ok,line};
}
function freshVM(screen,v){
 const {snap,state,ageS,eta,expected,now}=v,C=44;
 let text,frac=1;
 if(state==='connecting')text='Connecting to Titan…';
 else if(state==='paused')text='Readings paused';
 else if(state==='none')text=!snap.attached?'Not connected to the network':finite(ageS)?`No new reading for ${ageS} s`:snap.stale||!snap.connected?'Waiting for the Titan…':'No data';
 else if(state==='first')text="Waiting for the modem's first reading.";
 else if(state==='waiting'){text='Waiting for the modem…';}
 else if(state==='old')text=`Reading ${ageS} s old`;
 else{
  const p50=eta?.p50,next=eta?.overdue||(finite(p50)&&p50<=500)?'next any moment':finite(p50)?`next in about ${Math.max(1,Math.round(p50/1000))} s`:'';
  text=[ageS<1?'New reading':`Reading ${ageS} s old`,next].filter(Boolean).join(' · ');
  frac=finite(v.s.t)?clamp((now-v.s.t)/Math.max(500,expected),0,1):0;
 }
 const pose=screen.pose;
 const heading=pose&&finite(pose.heading)?pose.relative?`${Math.round(pose.heading)}° relative`:`${Math.round((pose.heading+360)%360)}°${pose.declination==null?' magnetic':''}`:'';
 const age=snap&&finite(snap.collectedAt)?Math.max(0,Math.floor((now-snap.collectedAt)/1000)):0;
 // Names the poll, not the reading, so "polled just now" beside an old reading is not a contradiction.
 const collector=!snap?'Connecting…':snap.connected&&!snap.paused?(screen.kind==='device'&&age>=2?`Titan polled ${age}s ago`:'Titan polled just now'):snap.paused?'Readings paused':`${age}s since update`;
 return {text,offset:C*frac,heading,collector};
}
function markVM(screen,v){
 if(screen.capture){const c=screen.capture,need=c.need||3;return {label:safe(()=>c.label())||'Hold still',disabled:true,busy:true,progress:clamp((c.got?.length||0)/need,0,1)};}
 return {label:'Mark this position',disabled:!screen._markEnabled(v.snap,v.now),busy:false,progress:0};
}
function actionsVM(screen,v){
 const i=STEPS.findIndex(([id])=>id===screen.step),next=STEPS[i+1];
 const bs=safe(()=>screen.bracket.state)||'idle',lockActive=screen._lock()==='watching'||screen._lock()==='dropped';
 return {undo:(screen.session.positions||[]).length>0&&!screen.capture,cancel:!!screen.capture||(bs!=='idle'&&bs!=='done')||lockActive,
  bracket:screen.step==='peak'&&!screen.capture&&(bs==='idle'||bs==='done')&&!(screen.pose&&!screen.pose.relative&&screen.bearing?.valid),
  lock:screen.step==='confirm'&&!screen.capture&&!lockActive,next:!!next,nextText:next?`Next: ${next[1]} ›`:'',
  suggest:!!next&&!['none','connecting','first'].includes(v.state)&&screen._suggest(v.now)};
}
function meterVM(screen,v,key){
 const M=METER[key],isQ=key==='sinr',e=isQ?v.q:v.s,ok=isQ?v.qOk:v.sigOk,raw=e.raw;
 const g=ok?gradeOf(M.metric,raw):null,best=isQ?v.bestPos?.quality?.mean:v.bestPos?.signal?.mean;
 const w=v.paused?'Paused':!ok?'No data':word(key,g)||'—';
 const ci=!ok?'':isQ&&e.source==='sinr'?'1 dB steps':finite(e.sd)?`±${(1.96*e.sd).toFixed(1)}`:'';
 const lo=pct(e.lo,M.min,M.max),hi=pct(e.hi,M.min,M.max);
 return {ok,value:ok?fx(raw):'—',width:ok?pct(raw,M.min,M.max):0,grade:g||'',word:w,ci,bandL:lo,bandW:ok&&finite(e.lo)&&finite(e.hi)?Math.max(0,hi-lo):0,
  best:finite(best)?pct(best,M.min,M.max):null,aria:ok?`${M.label} ${fx(raw)} ${M.unit}, ${w.toLowerCase()}`:`${M.label} ${w.toLowerCase()}`,now:ok?raw.toFixed(1):''};
}
function meterHTML(screen,v,key){
 const M=METER[key],m=meterVM(screen,v,key);
 return `<div class="align-meter${m.ok?'':' gauge-unavailable'}" data-gauge="${key}" data-grade="${m.grade}" role="meter" aria-valuemin="${M.min}" aria-valuemax="${M.max}"${m.ok?` aria-valuenow="${m.now}"`:''} aria-valuetext="${m.aria}">
  <div class="align-meter-head"><span class="eyebrow">${M.label}</span><strong><span data-live="${key}">${m.value}</span><small>${M.unit}</small></strong><span class="align-meter-ci" data-align-ci="${key}">${m.ci}</span><span class="align-grade" data-quality="${key}" data-grade="${m.grade}">${m.word}</span></div>
  <div class="align-meter-track"><i class="gauge-band" style="left:${m.bandL.toFixed(1)}%;width:${m.bandW.toFixed(1)}%"></i><i class="gauge-value" style="width:${m.width.toFixed(1)}%"></i><i class="gauge-best"${m.best==null?' hidden':` style="left:${m.best.toFixed(1)}%"`}></i></div>
 </div>`;
}
function hintHTML(g,esc){
 const arrow=ARROWS[g.arrow]||'';
 return `<span class="align-arrow" data-arrow="${arrow?g.arrow:'none'}" aria-hidden="true">${arrow}</span><div><strong>${esc(g.text||'')}</strong><p>${esc(g.detail||'')}</p></div>`;
}
function bannerHTML(screen,v,esc){
 const parts=(screen.findings||[]).filter(f=>f.severity==='block').map(f=>`<p><strong>${esc(f.title)}</strong> ${esc(f.action||'')}</p>`);
 const cc=screen.cellChange;
 if(cc&&v.now-cc.t<CELL_BANNER_MS)parts.unshift(`<p><strong>Now on PCI ${esc(cc.to)}${cc.from!=null&&cc.from!==cc.to?` (was ${esc(cc.from)})`:''}.</strong> That is a different sector.</p>`);
 if(screen._lock()==='dropped'){const d=screen.session.lock?.drop;parts.push(`<p><strong>Dropped${finite(d)?` ${d.toFixed(1)} dB`:''} while tightening.</strong> Loosen and nudge back.</p>`);}
 return parts.join('');
}
function stripSVG(screen,v){
 const rs=(v.est?.readings||[]).filter(r=>finite(r.raw)).slice(-STRIP_N);
 if(!rs.length)return `<text class="align-strip-empty" x="0" y="34">Readings appear here, one bar each.</text>`;
 const vals=rs.map(r=>r.raw),peak=screen.peak.peak?.value;
 let lo=Math.min(...vals),hi=Math.max(...vals,finite(peak)?peak:-Infinity);
 if(hi-lo<6){const m=(hi+lo)/2;lo=m-3;hi=m+3;}lo-=1;hi+=0.5;
 const W=400/STRIP_N,y=x=>56-clamp((x-lo)/(hi-lo),0,1)*54,best=vals.indexOf(Math.max(...vals)),x0=400-rs.length*W;
 const band=rs.map((r,i)=>finite(r.est)&&finite(r.sd)?[x0+i*W+W/2,y(r.est+1.96*r.sd),y(r.est-1.96*r.sd)]:null).filter(Boolean);
 const bandPath=band.length>1?`<path class="band" d="M${band.map(b=>`${b[0].toFixed(1)} ${b[1].toFixed(1)}`).join('L')}L${band.slice().reverse().map(b=>`${b[0].toFixed(1)} ${b[2].toFixed(1)}`).join('L')}Z"/>`:'';
 const bars=rs.map((r,i)=>{const top=y(r.raw),cls=i===best?'bar is-best':i===rs.length-1?'bar is-new':'bar';
  return `<rect class="${cls}" x="${(x0+i*W+1).toFixed(1)}" y="${top.toFixed(1)}" width="${(W-2).toFixed(1)}" height="${(56-top).toFixed(1)}" vector-effect="non-scaling-stroke"/>`;}).join('');
 const pl=finite(peak)?`<line class="peak" x1="0" x2="400" y1="${y(peak).toFixed(1)}" y2="${y(peak).toFixed(1)}" vector-effect="non-scaling-stroke"/>`:'';
 return bandPath+bars+pl;
}
const bearingVisible=s=>(s.points||[]).length>0;
function bearingCaption(s){
 const b=s.bearing;
 if(!b)return (s.points||[]).length?`${s.points.length} headed reading${s.points.length===1?'':'s'}. Mark positions across 20° or more for a bearing.`:'';
 if(!b.valid)return b.reason==='span'?'Spread your marks across at least 20°.':'Add headed readings in more directions.';
 const rec=Math.round(((b.recommended%360)+360)%360);
 return `${b.relative?'Best about':'Best near'} ${rec}°${b.relative?' (relative)':''} · beam about ${Math.round(b.theta3)}°${b.fitOk?'':' · irregular fit'}${s.bearingNote?' · '+s.bearingNote:''}`;
}
function bearingSVG(screen,v){
 const pts=screen.points||[];if(!pts.length)return '';
 const b=screen.bearing?.valid?screen.bearing:null;
 const ref=b?b.recommended:(S.circularMean?safe(()=>S.circularMean(pts.map(p=>p.heading))):null)??pts[0].heading;
 const ds=pts.map(p=>wrap180(p.heading-ref)),span=Math.max(30,...ds.map(Math.abs))+10;
 const ys=pts.map(p=>p.y),lo=Math.min(...ys)-1,hi=Math.max(...ys)+1;
 const X=d=>200+d/span*190,Y=y=>80-(y-lo)/(hi-lo)*74;
 const deg=d=>{const h=((ref+d)%360+360)%360;return `${Math.round(h)}°`;};
 let out=`<line class="axis" x1="0" x2="400" y1="82" y2="82"/><text x="10" y="96">${deg(-span)}</text><text x="390" y="96" text-anchor="end">${deg(span)}</text><text x="10" y="8">${num(hi,0)} dBm</text>`;
 if(b){const [a,c]=b.hdi68||[];if(finite(a)&&finite(c)){const xa=X(wrap180(a-ref)),xc=X(wrap180(c-ref));out+=`<rect class="hdi" x="${Math.min(xa,xc).toFixed(1)}" y="0" width="${Math.abs(xc-xa).toFixed(1)}" height="82"/>`;}
  out+=`<line class="rec" x1="200" x2="200" y1="0" y2="82"/><text class="rec-label" x="200" y="96" text-anchor="middle">${b.relative?'best':deg(0)}</text>`;}
 const pose=screen.pose;
 if(pose&&finite(pose.heading)){const x=X(wrap180(pose.heading-ref));if(x>=0&&x<=400)out+=`<line class="now" x1="${x.toFixed(1)}" x2="${x.toFixed(1)}" y1="0" y2="82"/>`;}
 const posSet=new Set((screen.session.positions||[]).filter(p=>p.heading).map(p=>`${p.heading.deg}/${p.signal?.mean}`));
 out+=pts.map((p,i)=>posSet.has(`${p.heading}/${p.y}`)?`<rect class="pos" x="${(X(ds[i])-3.5).toFixed(1)}" y="${(Y(p.y)-3.5).toFixed(1)}" width="7" height="7" vector-effect="non-scaling-stroke"/>`
  :`<circle class="pt" cx="${X(ds[i]).toFixed(1)}" cy="${Y(p.y).toFixed(1)}" r="2.2"/>`).join('');
 return out;
}
function predictHTML(screen,v){
 const p=screen.prediction,dl=v.snap?.throughput?.dlBps;
 const now=finite(dl)&&dl>=5e6?`<p class="align-now" data-align-now>Now: ${mbps(dl/1e6)} Mbps measured</p>`:'<p class="align-now" data-align-now hidden></p>';
 if(!p)return `<span class="eyebrow">Link prediction</span><p class="align-quiet">Waiting for a quality reading.</p>${now}`;
 const n=p.carriers?.length||1,range=finite(p.dlLo)&&finite(p.dlHi)&&Math.round(p.dlLo)!==Math.round(p.dlHi)?`${mbps(p.dlLo)}–${mbps(p.dlHi)}`:mbps(p.dlMbps);
 const pot=clamp(Math.round(p.potential??0),0,100);
 return `<span class="eyebrow">Link prediction</span><strong>Expected DL ${range} Mbps</strong><small>${n} carrier${n===1?'':'s'}${p.dlModulation?' · '+escText(p.dlModulation):''}${finite(p.ulMbps)?` · UL about ${mbps(p.ulMbps)} Mbps`:''}</small>
  <div class="align-potential"><span>Link potential</span><div class="align-potential-track"><i style="width:${pot}%"></i></div><b>${pot}%</b></div>
  <p class="align-foot">Idle-sector capacity, not a speed promise.${(p.assumptions||[]).length?' '+escText(p.assumptions.join('. '))+'.':' TDD 2/7 assumed.'}</p>${now}`;
}
function positionRow(p,i,{best,verdicts,basis},esc,prev=false){
 const n=p.index??i+1,isBest=!prev&&best===p.id,c=verdicts?.get?.(p.id);
 const bySignal=basis==='signal'&&finite(p.signal?.mean);
 const bits=[bySignal?(finite(p.quality?.mean)?`Quality ${num(p.quality.mean)} dB`:null):finite(p.signal?.mean)?`${num(p.signal.mean)} dBm`:null,
  !bySignal&&finite(p.signal?.se)?`±${(1.96*p.signal.se).toFixed(1)}`:null,`PCI ${p.pci??'—'}`,
  p.heading&&finite(p.heading.deg)?`${Math.round(p.heading.deg)}°${p.heading.relative?' rel':''}`:null,finite(p.n)?`${p.n} reading${p.n===1?'':'s'}`:null,
  p.flags?.lowConfidence?'Low confidence':null,p.flags?.unsteady?'Unsteady':null,p.flags?.qualityHeld?'Quality held':null].filter(Boolean).join(' · ');
 const score=!bySignal&&finite(p.quality?.mean)?`${fx(p.quality.mean)}<small>dB quality</small>`:`${num(p.signal?.mean)}<small>dBm signal</small>`;
 if(prev)return `<div class="position-prev"><span class="position-badge">${esc(n)}</span><div><strong>Position ${esc(n)}</strong><small>${esc(bits)}</small></div><div class="position-score">${score}</div></div>`;
 const verdict=isBest?`<span class="position-verdict" data-verdict="best">Best by ${basis==='quality'?'quality':'signal'}</span>`
  :c?`<span class="position-verdict" data-verdict="${esc(c.verdict)}">${esc(verdictText(c,basis))}</span>`:'';
 return `<div class="position" data-position="${esc(p.id)}"${isBest?' data-best':''}><span class="position-badge">${esc(n)}</span><div><strong>Position ${esc(n)}${isBest?' <span class="pill pill-green">Best</span>':''}</strong><small>${esc(bits)}</small>${verdict}</div><div class="position-score">${score}</div></div>`;
}
function positionsHTML(screen,esc,icon){
 const cur=screen.session.positions||[],arch=(screen.session.archived||[]).filter(g=>g.positions?.length);
 const b=cur.length?safe(()=>screen.session.best()):null,verdicts=cur.length>1?safe(()=>screen.session.verdicts(),new Map()):new Map();
 const meta={best:b?.position?.id,basis:b?.basis,verdicts};
 const rows=cur.length?cur.map((p,i)=>positionRow(p,i,meta,esc)).join('')
  :`<div class="position-empty">${icon('MapPin')}<strong>No saved positions</strong><p>Mark this spot, adjust the antenna, then mark again to compare.</p></div>`;
 return rows+arch.map(g=>`<details class="position-prev-group"><summary>Previous cell · PCI ${esc(g.pci)} <small>(${g.positions.length})</small></summary>${g.positions.map((p,i)=>positionRow(p,i,{},esc,true)).join('')}</details>`).join('');
}
function findingsHTML(screen,esc){
 const record=screen.step==='record',all=screen.findings||[];
 const layout=record?'record':isDesktop()?'desktop':isLandscape()?'landscape':'portrait';
 // Blocks live in the banner; this card carries the rest, capped per layout (spec 5.3).
 const list=record?all:(D.pick?D.pick(all,layout):all).filter(f=>f.severity!=='block').slice(0,layout==='desktop'?3:1);
 return list.map(f=>`<div class="align-finding" data-severity="${esc(f.severity)}" data-finding="${esc(f.id)}"><strong>${esc(f.title)}</strong>${f.action?`<p>${esc(f.action)}</p>`:''}${f.detail?`<small>${esc(f.detail)}</small>`:''}</div>`).join('');
}
const ACC_FMT={rsrp:v=>`${num(v)} dBm`,quality:v=>`${num(v)} dB`,rsrq:v=>`${num(v)} dB`,imbalance:v=>`${num(Math.abs(v))} dB`,margin:v=>`${num(v)} dB`,steadiness:v=>`${num(v)} dB`};
function recordHTML(screen,v,esc,icon){
 const ctx=screen._dctx(v.now),acc=safe(()=>D.acceptance(ctx))||{rows:[],verdict:'incomplete'};
 const row=m=>acc.rows.find(r=>r.metric===m);
 const fmt=r=>typeof r.value==='number'?(ACC_FMT[r.metric]?.(r.value)??`${num(r.value)} ${r.unit||''}`):r.value==null?esc(r.note||'—'):esc(r.value);
 let sum;
 if(acc.verdict==='incomplete')sum='Mark the final position to grade the install.';
 else if(acc.verdict==='fail')sum='Not ready: '+acc.rows.filter(r=>r.grade==='fail').map(r=>`${r.label} ${fmt(r).replace(/<[^>]+>/g,'')}`).join(', ')+'.';
 else{const r=row('rsrp'),q=row('quality'),m=row('margin');
  sum=`${acc.verdict==='pass'?'Good install.':'Passes with notes.'} Signal ${finite(r?.value)?num(r.value,0):'—'} dBm, quality ${finite(q?.value)?num(q.value):'—'} dB${finite(m?.value)?`, ${num(m.value,0)} dB clear of the next cell`:''}.`;
  if(acc.verdict==='pass-notes')sum+=' Check: '+acc.rows.filter(x=>x.grade==='marginal').map(x=>x.label).join(', ')+'.';}
 const gw=(r)=>r.grade?`<span class="align-grade" data-grade="${esc(r.grade)}">${r.metric==='grant'?(r.grade==='fail'?'Fail':'Pass'):word(r.metric==='rsrp'?'rsrp':'q',r.grade)}</span>`:'—';
 const table=acc.rows.length?`<div class="table-wrap"><table><thead><tr><th>Check</th><th>Value</th><th>Grade</th></tr></thead><tbody>${acc.rows.map(r=>`<tr><td>${esc(r.label)}</td><td class="mono">${fmt(r)}</td><td>${gw(r)}</td></tr>`).join('')}</tbody></table></div>`:'';
 const pos=screen.session.positions||[],b=safe(()=>screen.session.best()),verdicts=pos.length>1?safe(()=>screen.session.verdicts(),new Map()):new Map();
 const ptable=pos.length?`<div class="table-wrap"><table class="align-pos-table"><thead><tr><th>#</th><th>Signal</th><th>Quality</th><th>RX1 / RX2</th><th>Heading</th><th>Verdict</th></tr></thead><tbody>${pos.map((p,i)=>{const c=verdicts.get?.(p.id);
  return `<tr><td class="mono">${esc(p.index??i+1)}</td><td class="mono">${num(p.signal?.mean)}</td><td class="mono">${num(p.quality?.mean)}</td><td class="mono">${(p.rx||[]).slice(0,2).map(x=>num(x)).join(' / ')||'—'}</td><td class="mono">${p.heading&&finite(p.heading.deg)?Math.round(p.heading.deg)+'°':'—'}</td><td>${b?.position?.id===p.id?'Best':esc(verdictText(c,b?.basis))}</td></tr>`;}).join('')}</tbody></table></div>`:'';
 return `<div class="card-head"><h2>Install record</h2><span class="muted text-xs">${esc(new Date(v.now).toLocaleDateString())}</span></div>
  <p class="align-record-sum" data-verdict="${esc(acc.verdict)}">${sum}</p>${table}${ptable}
  <div class="align-record-actions"><button type="button" class="btn" data-align-action="export-json">${icon('Download')}Session JSON</button><button type="button" class="btn" data-align-action="print">${icon('ScanLine')}Print</button></div>`;
}
const DETAILS=[['live:chains','RX1 / RX2'],['live:rsrq','RSRQ'],['bestchain','Best chain'],['imbalance','RX balance'],['margin','Clear of next cell'],['quality','Quality per chain'],
 ['cell','Cell'],['tx','TX power · MIMO'],['cadence','Readings']];
function detailText(screen,v,k){
 const {s,q,snap,est}=v,c=snap?.cell||{};
 if(k==='bestchain')return v.sigOk?`${fx(s.best)} dBm`:'—';
 if(k==='imbalance')return finite(s.imbalance)?`${signed(s.imbalance)} dB`:'—';
 if(k==='margin'){const m=safe(()=>D.derive(screen._dctx(v.now))?.margin);return m&&finite(m.db)?`${fx(m.db)} dB over PCI ${m.pci}${m.clash?' · PCI clash':m.mod3?' · mod-3':''}`:snap?'No other cell heard':'—';}
 if(k==='quality')return v.qOk?(q.source==='sinr'?`SINR ${fx(q.sinr??q.raw)} dB (1 dB steps)`:(q.chains||[]).map(x=>fx(x)).join(' / ')+' dB'):'—';
 if(k==='cell')return snap?[c.earfcn!=null&&`EARFCN ${c.earfcn}`,c.band&&`Band ${c.band}`,c.tac!=null&&`TAC ${c.tac}`,c.eci!=null&&`ECI ${c.eci}`].filter(Boolean).join(' · ')||'—':'—';
 if(k==='tx'){const r=snap?.radio;return r?[finite(r.txPowerDbm)?`${fx(r.txPowerDbm)} dBm`:null,r.mimo].filter(Boolean).join(' · ')||'—':'—';}
 if(k==='cadence'){const n=est?.signal?.n,ms=est?.cadence?.signalMs;return finite(n)?`${n} · about every ${finite(ms)?(ms/1000).toFixed(1):'—'} s`:'—';}
 return '—';
}
function carriersHTML(v,esc){
 const cars=v.snap?.carriers||[];if(!cars.length)return '';
 return `<div class="table-wrap"><table><thead><tr><th>Carrier</th><th>PCI</th><th>EARFCN</th><th>BW</th><th>RSRP</th><th>CINR</th></tr></thead><tbody>${cars.map(c=>`<tr><td>${c.role==='pcc'?'PCC':'SCC'+esc(c.index)}${c.active===false?' (idle)':''}</td><td class="mono">${esc(c.pci??'—')}</td><td class="mono">${esc(c.earfcn??'—')}</td><td class="mono">${finite(c.bandwidthMhz)?c.bandwidthMhz+' MHz':'—'}</td><td class="mono">${(c.rsrpChains||[]).filter(finite).map(x=>fx(x)).join(' / ')||'—'}</td><td class="mono">${(c.cinrChains||[]).filter(finite).map(x=>fx(x)).join(' / ')||fx(c.sinr)}</td></tr>`).join('')}</tbody></table></div>`;
}

// ---- patch ------------------------------------------------------------------
AlignScreen.prototype._patch=function(now){
 const el=this.el;if(!el?.isConnected)return;
 const v=this._view(now),$=s=>el.querySelector(s),ctx=this._ctx||{},esc=ctx.esc||escText,icon=ctx.icon||(()=>'');
 const html=(node,value)=>{if(node&&this._html.get(node)!==value){this._html.set(node,value);node.innerHTML=value;}};
 const text=(node,value)=>{if(node&&node.textContent!==value)node.textContent=value;};
 const attr=(node,name,value)=>{if(!node)return;if(value===null||value===false)node.removeAttribute(name);else if(node.getAttribute(name)!==String(value))node.setAttribute(name,value===true?'':value);};
 const show=(node,on)=>{if(node&&node.hidden===!!on)node.hidden=!on;};
 el.dataset.step=this.step;el.dataset.freshnessState=v.state;el.classList.toggle('is-sun',this.prefs.sun);if(typeof document!=='undefined')document.documentElement?.classList?.toggle?.('align-sun',this.prefs.sun);el.style.setProperty('--align-tween',v.tween+'ms');
 const banner=bannerHTML(this,v,esc),bn=$('[data-align-banner]');html(bn,banner);show(bn,!!banner);
 const sug=actionsVM(this,v);
 el.querySelectorAll('[data-align-steps] [data-step]').forEach((b,i)=>{attr(b,'aria-current',b.dataset.step===this.step?'step':null);b.classList.toggle('is-suggested',sug.suggest&&STEPS[STEPS.findIndex(([id])=>id===this.step)+1]?.[0]===b.dataset.step);});
 const big=bigVM(this,v);html($('[data-align-eyebrow]'),big.eyebrow);
 text($('[data-live=pci]'),String(cellPci(v)));text($('[data-align-enb]'),enbText(v));
 const bigEl=$('[data-align-big]');if(bigEl)setLiveText(bigEl,big.text);
 const tr=$('[data-align-trend]');if(tr){text(tr,big.trend);tr.dataset.dir=big.dir;show(tr,!!big.trend);}
 const cap=$('[data-align-caption]'),capOn=this.prefs.captions&&this.caption&&now-this.caption.t<4000;if(cap){text(cap,capOn?this.caption.text:'');show(cap,capOn);}
 const pk=peakVM(this,v);
 const fill=$('.align-peak-fill');if(fill)fill.style.width=pk.fill.toFixed(1)+'%';
 const ps=$('.align-peak-session');if(ps){ps.style.left=pk.session.toFixed(1)+'%';show(ps,pk.showSession);}
 const pr=$('.align-peak-recent');if(pr){pr.style.left=pk.recent.toFixed(1)+'%';show(pr,pk.showRecent);}
 const pl=$('[data-align-peakline]');if(pl&&this._html.get(pl)!==pk.line){const first=!this._html.has(pl);this._html.set(pl,pk.line);pl.innerHTML=pk.line;if(!first&&!reduceMotion())pl.animate?.([{opacity:.55},{opacity:1}],{duration:220});}
 for(const key of ['sinr','rsrp']){
  const m=meterVM(this,v,key),node=$(`[data-gauge=${key}]`);if(!node)continue;
  node.classList.toggle('gauge-unavailable',!m.ok);node.dataset.grade=m.grade;attr(node,'aria-valuenow',m.ok?m.now:null);attr(node,'aria-valuetext',m.aria);
  text(node.querySelector(`[data-live=${key}]`),m.value);text(node.querySelector('[data-align-ci]'),m.ci);
  const g=node.querySelector('[data-quality]');if(g){text(g,m.word);g.dataset.grade=m.grade;}
  const val=node.querySelector('.gauge-value'),w=m.width.toFixed(1)+'%';if(val&&val.style.width!==w)val.style.width=w;
  const band=node.querySelector('.gauge-band');if(band){band.style.left=m.bandL.toFixed(1)+'%';band.style.width=m.bandW.toFixed(1)+'%';}
  const best=node.querySelector('.gauge-best');if(best){show(best,m.best!=null);if(m.best!=null)best.style.left=m.best.toFixed(1)+'%';}
 }
 const fr=freshVM(this,v);
 const ring=$('.align-ring'),age=$('.align-ring-age');if(age)attr(age,'stroke-dashoffset',fr.offset.toFixed(1));
 if(ring&&this.pingAt&&this.pingAt!==this._pinged){this._pinged=this.pingAt;ring.classList.remove('is-ping');void ring.getBoundingClientRect?.();ring.classList.add('is-ping');}
 text($('[data-align-fresh-text]'),fr.text);const hd=$('[data-align-heading]');text(hd,fr.heading);show(hd,!!fr.heading);text($('[data-freshness]'),fr.collector);
 html($('[data-align-strip]'),stripSVG(this,v));text($('[data-align-strip-n]'),stripCount(v));
 const g=this.guide||{},hint=$('[data-hint]');if(hint){hint.dataset.tone=g.tone||'quiet';const h=hintHTML(g,esc);if(this._html.get(hint)!==h){const first=!this._html.has(hint);this._html.set(hint,h);hint.innerHTML=h;if(!first&&!reduceMotion())hint.animate?.([{opacity:.5,transform:'translateY(2px)'},{opacity:1,transform:'none'}],{duration:220,easing:'cubic-bezier(.2,.7,.2,1)'});}}
 show($('[data-align-start]'),startVisible(this));
 const mk=markVM(this,v),mb=$('[data-action=mark]');if(mb){mb.disabled=mk.disabled;attr(mb,'aria-busy',mk.busy?'true':null);mb.style.setProperty('--cap',String(mk.progress));html(mb.querySelector('[data-mark-icon]'),icon(mk.busy?'Clock3':'Plus'));text(mb.querySelector('[data-mark-label]'),mk.label);}
 const ab=n=>$(`[data-align-action=${n}]`);
 const undo=ab('undo');if(undo)undo.disabled=!sug.undo;show(ab('cancel'),sug.cancel);show(ab('bracket'),sug.bracket);show(ab('lock'),sug.lock);
 const nx=ab('next');if(nx){show(nx,sug.next);text(nx,sug.nextText);nx.classList.toggle('is-suggested',sug.suggest);}
 const audioOn=!!this._audio?.enabled,wakeOn=!!this._wake?.active;
 html($('[data-action=audio]'),icon(audioOn?'Volume2':'VolumeX')+(audioOn?'Sound on':'Sound off'));
 html($('[data-action=pause]'),icon(v.paused?'Play':'Pause')+(v.paused?'Resume':'Pause'));
 html($('[data-action=wake]'),icon('Sun')+(wakeOn?'Screen awake':'Keep awake'));
 attr(ab('compass'),'aria-pressed',String(!!this._compass?.active));attr(ab('sunlight'),'aria-pressed',String(this.prefs.sun));attr(ab('captions'),'aria-pressed',String(this.prefs.captions));
 html($('[data-align-best-sum]'),bestSum(v));
 const list=$('#positions'),before=list?.querySelectorAll('.position').length??0;html(list,positionsHTML(this,esc,icon));
 if(this.revealNew&&list){this.revealNew=false;const rows=list.querySelectorAll('.position');if(rows.length>before)reveal(rows[rows.length-1]);}
 const fh=findingsHTML(this,esc);html($('[data-align-findings]'),fh);show($('[data-align-findings-card]'),!!fh);
 const rec=$('[data-align-record]');show(rec,this.step==='record');if(this.step==='record')html(rec,recordHTML(this,v,esc,icon));
 text($('[data-align-source]'),sourceText(this,v));
 show($('[data-align-bearing-box]'),bearingVisible(this));if(bearingVisible(this)){html($('[data-align-bearing]'),bearingSVG(this,v));text($('[data-align-bearing-note]'),bearingCaption(this));}
 html($('[data-align-predict]'),predictHTML(this,v));
 text($('[data-live=chains]'),chainsText(v));text($('[data-live=rsrq]'),v.sigOk||v.state==='paused'?fx(v.est?.rsrq?.raw):'—');
 for(const [k] of DETAILS)if(!k.startsWith('live:'))text($(`[data-align-d=${k}]`),detailText(this,v,k));
 html($('[data-align-d=carriers]'),carriersHTML(v,esc));
};

function download(name,value,type){
 if(typeof document==='undefined')return;
 const url=URL.createObjectURL(new Blob([value],{type})),a=document.createElement('a');
 a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),2000);
}
