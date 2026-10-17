import {register} from 'node:module';
import test from 'node:test';
import assert from 'node:assert/strict';
register('data:text/javascript,export async function load(u,c,n){return u.endsWith(".css")?{format:"module",source:"",shortCircuit:true}:n(u,c)}');
globalThis.matchMedia = () => ({matches:false, addEventListener(){}});
globalThis.document = {addEventListener(){}, removeEventListener(){}, hidden:false, documentElement:{classList:{contains:()=>false}}};
const {renderAlign, AlignScreen} = await import('../src/align/view.js');

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[c]));
const ctx = (over = {}) => ({esc, icon:() => '<svg class="icon"></svg>',
  button:(text, action, ic = '', cls = '') => `<button type="button" class="btn ${cls}" data-action="${action}">${text}</button>`,
  head:(eyebrow, title, sub, action = '') => `<div class="page-head"><div><h1>${title}</h1><p class="page-sub">${sub}</p></div>${action}</div>`,
  pill:(t, type = 'green') => `<span class="pill pill-${type}">${t}</span>`, focus:false, config:{pciMode:'Automatic', pciTargets:[]}, ...over});
const count = (html, needle) => html.split(needle).length - 1;
const record = (index, signal, quality, pci = 190) => ({id:`p${index}`, index, t:1000 * index, pci, eci:2616332, earfcn:56040, n:3, nQuality:1,
  flags:{lowConfidence:false, unsteady:false, qualityHeld:false}, signal:{mean:signal, se:0.2, lo:signal - 0.6, hi:signal + 0.6, n:3}, best:signal + 1, rx:[signal + 1, signal - 1.5],
  imbalance:2.5, quality:{mean:quality, se:0.3, lo:quality - 1, hi:quality + 1, n:1, source:'cinr'}, sinr:Math.round(quality), rsrq:-9, margin:12, heading:null, predict:null,
  readings:[{t:0, signal, rx:[signal, signal], quality}]});
const snap = (over = {}) => ({kind:'demo', receivedAt:Date.now(), collectedAt:Date.now(), connected:true, attached:true, stale:false, paused:false,
  cell:{pci:190, earfcn:56040, band:'48', enbId:10220, cellId:12, tac:10, eci:2616332},
  signal:{seq:1, reading:1, t:Date.now(), readingT:Date.now(), rsrp:[-84.2, -85.1], rsrq:[-9.1, -9.4], rssi:[-60, -61], heartbeat:false, source:'sim', periodMs:null},
  quality:{seq:1, t:Date.now(), cinr:[18.6, 18.6], sinr:19, sinrStep:1, source:'sim'}, activeChains:2, neighbours:[], carriers:[],
  radio:{cqi:10, ri:2, dlModulation:'64QAM', dlMcs:17, ulModulation:null, ulMcs:null, configured:1, active:1, txPowerDbm:2, mimo:'TM4'},
  throughput:{dlBps:null, ulBps:null}, sas:{grant:'Authorized', registration:'Registered'}, gps:null, refresh:null, ...over});

test('required hooks appear exactly once', () => {
  const html = renderAlign(ctx());
  for (const hook of ['data-live="sinr"', 'data-live="rsrp"', 'data-live="pci"', 'data-action="mark"', 'id="positions"', 'data-gauge="sinr"', 'data-gauge="rsrp"',
    'data-hint', 'data-freshness>', 'data-action="export"', 'data-action="clear-positions"', 'data-action="audio"', 'data-action="pause"', 'data-action="wake"',
    'data-align-big', 'data-align-announce', 'data-live="rsrq"', 'data-live="chains"', 'data-live="best"', '<h1>'])
    assert.equal(count(html, hook), 1, hook);
  assert.equal(count(html, 'Mark this position'), 1);
  assert.match(html, /<h1>Antenna alignment<\/h1>/);
  const sinr = html.indexOf('data-gauge="sinr"'), rsrp = html.indexOf('data-gauge="rsrp"'), live = html.indexOf('data-live="sinr"');
  assert.ok(sinr < live && live < rsrp, 'Quality value sits inside the Quality meter');
  assert.ok(html.indexOf('data-live="rsrp"') > rsrp);
  assert.equal(count(html, 'data-action="open-lock"'), 0);
  assert.equal(count(renderAlign(ctx({config:{pciMode:'Preferred list', pciTargets:[{pci:190}]}})), 'data-action="open-lock"'), 1);
  assert.match(html, /data-step="find"/); assert.match(html, /data-freshness-state="connecting"/);
  assert.equal(count(html, 'gauge-unavailable'), 2);
  assert.match(html, /data-action="mark" disabled/);
});

test('positions: two rows, one Best pill, archived rows stay separate', () => {
  const screen = new AlignScreen({kind:'demo'});
  screen.session.add(record(1, -84.2, 18.4));
  screen.session.add(record(2, -86.5, 14.1));
  let html = screen.render(ctx());
  assert.equal(count(html, 'class="position"'), 2);
  assert.match(html, /Position 1/); assert.match(html, /Position 2/);
  assert.equal(count(html, 'pill-green">Best'), 1);
  assert.equal(count(html, 'class="position-prev"'), 0);
  screen.session.onCellChange(190, 142);
  html = screen.render(ctx());
  assert.equal(count(html, 'class="position"'), 0);
  assert.equal(count(html, 'class="position-prev"'), 2);
  assert.match(html, /Previous cell · PCI 190/);
});

test('live snapshot fills meters, freshness and the mark button', () => {
  const s = snap(), screen = new AlignScreen({kind:'demo'});
  screen.source = {kind:'demo', snapshot:() => s, subscribe:() => () => {}};
  screen.update();
  const html = screen.render(ctx());
  assert.match(html, /data-live="sinr">18\.6</);
  assert.match(html, /data-live="rsrp">-84\.6</);
  assert.match(html, /data-live="pci">190</);
  assert.match(html, /data-freshness>Titan polled just now</);
  assert.equal(count(html, 'gauge-unavailable'), 0);
  assert.doesNotMatch(html, /data-action="mark" disabled/);
  assert.match(html, /class="gauge-value" style="width:\d+\.\d%"/);
});

test('stale and paused states', () => {
  const screen = new AlignScreen({kind:'device'});
  let s = snap({connected:false, stale:true, collectedAt:Date.now() - 12000});
  screen.source = {kind:'device', snapshot:() => s, subscribe:() => () => {}};
  screen.update();
  let html = screen.render(ctx());
  assert.equal(count(html, 'gauge-unavailable'), 2);
  assert.match(html, /data-live="sinr">—</);
  assert.equal(count(html, '>No data<'), 2);
  assert.match(html, /data-freshness>12s since update</);
  assert.match(html, /data-action="mark" disabled/);
  s = snap({paused:true});
  screen.update();
  html = screen.render(ctx());
  assert.match(html, /data-quality="sinr" data-grade="[a-z]*">Paused</);
  assert.match(html, /data-freshness>Readings paused</);
  assert.match(html, /data-action="mark" disabled/);
});

test('capture label counts readings and Mark stays single', () => {
  const s = snap(), screen = new AlignScreen({kind:'demo'});
  screen.source = {kind:'demo', snapshot:() => s, subscribe:() => () => {}};
  screen.update(); screen.mark();
  assert.equal(screen.capturing, true);
  const html = screen.render(ctx());
  assert.match(html, /data-action="mark" disabled[^>]*>.*Hold still · reading 0 of 3/);
  assert.equal(count(html, 'data-action="mark"'), 1);
  screen.cancelCapture('user');
  assert.equal(screen.capturing, false);
});

test('cell change archives positions and raises the banner', () => {
  let s = snap(), screen = new AlignScreen({kind:'demo'});
  screen.source = {kind:'demo', snapshot:() => s, subscribe:() => () => {}};
  screen.update();
  screen.session.add(record(1, -84.2, 18.4));
  s = snap({cell:{...s.cell, pci:142, eci:2616333}, signal:{...s.signal, seq:2, reading:2}});
  screen.update();
  const html = screen.render(ctx());
  assert.equal(count(html, 'class="position"'), 0);
  assert.equal(count(html, 'class="position-prev"'), 1);
  assert.match(html, /Now on PCI 142 \(was 190\)/);
  assert.match(html, /data-live="pci">142</);
});

test('steps and record step', () => {
  const screen = new AlignScreen({kind:'demo'});
  screen.step = 'record';
  screen.session.add(record(1, -84.2, 18.4));
  const html = screen.render(ctx());
  assert.match(html, /data-step="record"/);
  assert.match(html, /data-step="record" aria-current="step"/);
  assert.match(html, /data-align-record aria-label="Install record">/);
  assert.match(html, /data-align-action="export-json"/);
  assert.match(html, /data-align-action="print"/);
  assert.equal(count(html, 'data-action="export"'), 1);
});

test('leave releases a wake lock that is wanted but not active yet', () => {
  const screen = new AlignScreen({kind:'demo'});
  let released = 0;
  screen._wake = {supported:true, active:false, async request() { return true; }, async release() { released++; }};
  screen.leave();
  assert.equal(released, 1);
});

test('positions on the signal basis show signal as the score and name the metric', () => {
  const screen = new AlignScreen({kind:'demo'});
  screen.session.add(record(1, -86.5, 29.6));
  screen.session.add(record(2, -81.0, 27.6));
  const html = screen.render(ctx());
  assert.match(html, /Best signal <strong data-live="best">−81\.0<\/strong> dBm/);
  assert.match(html, /Weaker signal \(−5\.5 dB\)/);
  assert.match(html, /−86\.5<small>dBm signal<\/small>/);
  assert.match(html, /Quality 29\.6 dB/);
});

test('no cell change from a blank ECI or stale data; D13 needs a marked position', () => {
  let s = snap(), screen = new AlignScreen({kind:'demo'});
  screen.source = {kind:'demo', snapshot:() => s, subscribe:() => () => {}};
  screen.update();
  s = snap({cell:{...s.cell, eci:null}, signal:{...s.signal, seq:2, reading:2}});
  screen.update();
  s = snap({cell:{...s.cell, eci:2616332}, signal:{...s.signal, seq:3, reading:3}});
  screen.update();
  assert.equal(screen.cellChange, null);
  s = snap({stale:true, connected:false, cell:{...s.cell, pci:142}});
  screen.update();
  assert.equal(screen.cellChange, null, 'stale data cannot announce a sector');
  assert.ok(!screen.findings.some(f => f.id === 'D13'));
});
