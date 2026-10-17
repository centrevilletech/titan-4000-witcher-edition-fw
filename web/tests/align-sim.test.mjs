import test from 'node:test';
import assert from 'node:assert/strict';
import {AlignSim, CADENCE, SCENARIOS} from '../src/align/sim.js';

const clock = (t0 = 1_000_000) => { const c = {t: t0, now: () => c.t}; return c; };
const make = (controls = {}, seed = 7) => {
  const c = clock(), sim = new AlignSim({seed, now: c.now, manual: true});
  sim.setControls(controls);
  sim.start();
  return {c, sim, run(ms, step = 50) { const end = c.t + ms; while (c.t < end) { c.t += step; sim.tick(c.t); } }};
};
const collect = sim => { const out = []; sim.subscribe(s => out.push(s)); return out; };

test('exports', () => {
  assert.deepEqual(SCENARIOS, ['normal','interference','imbalance','sidelobe','slow','fast']);
  assert.deepEqual(Object.keys(CADENCE), ['demo','realistic','fast']);
  assert.equal(new AlignSim({manual: true}).kind, 'demo');
});

test('importing touches no browser globals', () => {
  assert.equal(typeof globalThis.window, 'undefined');
});

test('snapshot has the documented shape', () => {
  const {sim, run} = make();
  run(5000);
  const s = sim.snapshot();
  for (const k of ['kind','receivedAt','collectedAt','connected','attached','stale','paused','cell','signal','quality','activeChains',
    'neighbours','carriers','radio','throughput','sas','gps','refresh']) assert.ok(k in s, k);
  assert.equal(s.kind, 'demo');
  assert.equal(s.connected, true);
  assert.equal(s.receivedAt, s.collectedAt);
  assert.deepEqual(Object.keys(s.cell).sort(), ['band','cellId','earfcn','eci','enbId','pci','tac']);
  assert.deepEqual(s.cell, {pci: 190, earfcn: 56040, band: '48', enbId: 10220, cellId: 12, tac: 10, eci: 2616332});
  const g = s.signal;
  assert.deepEqual(Object.keys(g).sort(), ['heartbeat','periodMs','reading','readingT','rsrp','rsrq','rssi','seq','source','t']);
  assert.equal(g.source, 'sim'); assert.equal(g.heartbeat, false);
  assert.ok(g.readingT <= g.t);
  for (const k of ['rsrp','rsrq','rssi']) {
    assert.equal(g[k].length, s.activeChains);
    for (const v of g[k]) assert.equal(Math.round(v * 10) / 10, v);
  }
  g.rssi.forEach((v, i) => assert.ok(Math.abs(v - (g.rsrp[i] + 20 - g.rsrq[i])) < 0.11));
  const q = s.quality;
  assert.deepEqual(Object.keys(q).sort(), ['cinr','seq','sinr','sinrStep','source','t']);
  assert.equal(q.cinr.length, 2); assert.equal(q.sinrStep, 1); assert.equal(q.sinr, Math.round(q.sinr));
  assert.deepEqual(s.neighbours.map(n => [n.pci, n.earfcn, n.coChannel]), [[189,56040,'pcc'],[216,56638,'scc1'],[207,56440,'scc2']]);
  for (const n of s.neighbours) assert.deepEqual(Object.keys(n).sort(), ['coChannel','earfcn','pci','rsrp','rsrq','rssi']);
  assert.deepEqual(s.carriers.map(c => [c.role, c.index, c.pci, c.earfcn]), [['pcc',0,190,56040],['scc',1,217,56638],['scc',2,208,56440]]);
  assert.equal(s.carriers[1].sinr, q.sinr - 4); assert.equal(s.carriers[2].sinr, q.sinr - 5);
  for (const c of s.carriers) for (const k of ['rsrpChains','rsrqChains','rssiChains','cinrChains','active','dlModulation','dlMcs','bandwidthMhz','sinr']) assert.ok(k in c, k);
  assert.deepEqual({cqi: s.radio.cqi, ri: s.radio.ri, dlModulation: s.radio.dlModulation, dlMcs: s.radio.dlMcs}, {cqi: 10, ri: 2, dlModulation: '64QAM', dlMcs: 17});
  assert.ok(s.throughput.dlBps >= 20e6 && s.throughput.dlBps <= 60e6);
  assert.deepEqual(s.sas, {grant: 'Authorized', registration: 'Registered'});
  assert.deepEqual(s.gps, {fix: true, latitude: 33.51849, longitude: -86.81036, altitudeM: 212});
  assert.deepEqual(s.refresh, {pending: false, cycleMs: null});
  const p = sim.pose();
  assert.equal(p.source, 'sim'); assert.equal(p.relative, false); assert.equal(p.valid, true);
  assert.ok(Math.abs(p.heading - (100 + 1.6 * 72)) < 8);
  assert.ok(Math.abs(p.magnetic - p.heading) < 10);
});

test('manual mode with a seed is deterministic', () => {
  const a = make({}, 42), b = make({}, 42), c = make({}, 43);
  const sa = collect(a.sim), sb = collect(b.sim), sc = collect(c.sim);
  a.run(20000); b.run(20000); c.run(20000);
  assert.ok(sa.length > 10);
  assert.deepEqual(sa, sb);
  assert.notDeepEqual(sa.map(s => s.signal?.rsrp), sc.map(s => s.signal?.rsrp));
});

test('seq increases every write, reading only at burst starts, quality every Nth reading', () => {
  const {sim, run} = make();
  const out = collect(sim);
  run(30000);
  const sig = out.map(s => s.signal);
  for (let i = 1; i < sig.length; i++) {
    assert.equal(sig[i].seq, sig[i - 1].seq + 1);
    assert.ok(sig[i].reading === sig[i - 1].reading || sig[i].reading === sig[i - 1].reading + 1);
    if (sig[i].reading === sig[i - 1].reading) {
      assert.equal(sig[i].readingT, sig[i - 1].readingT);
      assert.equal(sig[i].t - sig[i - 1].t, CADENCE.demo.burstGapMs);
    }
  }
  const last = sig.at(-1);
  assert.ok(last.seq > last.reading, 'demo bursts revise readings');
  const qualityReadings = new Set(out.filter((s, i) => i && s.quality.seq !== out[i - 1].quality.seq).map(s => s.signal.reading));
  for (const r of qualityReadings) assert.equal((r - 1) % CADENCE.demo.qualityEvery, 0);
});

test('variable cadence: demo gaps vary inside the profile, realistic is slower, fast is 1 Hz with reading === seq', () => {
  const starts = profile => {
    const {sim, run} = make({alignScenario: profile});
    const out = collect(sim);
    run(120000, 100);
    const t = [...new Map(out.map(s => [s.signal.reading, s.signal.readingT])).values()];
    return {gaps: t.slice(1).map((x, i) => x - t[i]), out};
  };
  const demo = starts('normal').gaps;
  assert.ok(demo.every(g => g >= 900 && g <= 1700), String(demo));
  assert.ok(Math.max(...demo) - Math.min(...demo) >= 300, 'gaps vary');
  const slow = starts('slow');
  assert.ok(slow.gaps.every(g => g >= 2600 && g <= 6500));
  const mean = slow.gaps.reduce((a, b) => a + b) / slow.gaps.length;
  assert.ok(mean > 3500 && mean < 5500, String(mean));
  const perReading = new Map();
  for (const s of slow.out) perReading.set(s.signal.reading, (perReading.get(s.signal.reading) ?? 0) + 1);
  assert.ok([...perReading.values()].slice(1, -1).every(n => n >= 2 && n <= 4));
  const fast = starts('fast');
  assert.ok(fast.gaps.every(g => Math.abs(g - 1000) <= 100));
  for (const s of fast.out) assert.equal(s.signal.reading, s.signal.seq);
  const q = fast.out.map(s => s.quality.seq);
  assert.ok(q.every((x, i) => !i || x === q[i - 1] + 1), 'fast updates quality on every reading');
});

test('beam pattern peaks at the configured bearing (slider 83, 233 deg)', () => {
  const {sim} = make();
  assert.equal(sim.truth().boresight, 233);
  const truth = [], mean = [];
  for (let q = 0; q <= 100; q++) {
    sim.setControls({quality: q});
    truth.push(sim.truth().rsrp[0]);
    let sum = 0;
    for (let k = 0; k < 12; k++) { sim.setControls({quality: q}); sim.setControls({quality: q + 1e-9}); sum += sim.snapshot().signal.rsrp[0]; }
    mean.push(sum / 12);
  }
  const argmax = a => a.indexOf(Math.max(...a));
  assert.equal(argmax(truth), 83);
  assert.ok(Math.abs(argmax(mean) - 83) <= 4, `noisy peak at ${argmax(mean)}`);
  assert.ok(mean[83] - mean[50] > 6 && mean[83] - mean[0] > 15);
  sim.setControls({quality: 83});
  assert.ok(Math.abs(sim.truth().offset) < 0.5);
});

test('imbalance scenario separates the chains by about 8 dB', () => {
  const diff = alignScenario => {
    const {sim, run} = make({alignScenario, quality: 83});
    const out = collect(sim);
    run(60000);
    const d = out.map(s => s.signal.rsrp[0] - s.signal.rsrp[1]);
    return d.reduce((a, b) => a + b) / d.length;
  };
  assert.ok(Math.abs(diff('imbalance') - 8) < 0.5);
  assert.ok(Math.abs(diff('normal') - 2.5) < 0.5);
});

test('side lobe scenario adds a local peak away from boresight', () => {
  const {sim} = make({alignScenario: 'sidelobe'});
  const at = q => { sim.setControls({quality: q}); return sim.truth().rsrp[0]; };
  const lobe = at(36.25);
  assert.ok(lobe - at(43) > 2.5 && lobe - at(30) > 2.5 && lobe < at(83) - 10);
});

test('setControls({quality}) emits synchronously in the demo profile, not in realistic', () => {
  const {sim} = make();
  const out = collect(sim);
  const before = sim.snapshot().signal.reading;
  sim.setControls({quality: 30});
  assert.equal(out.length, 1);
  assert.equal(out[0].signal.reading, before + 1);
  assert.ok(out[0].signal.rsrp[0] < -90);
  const slow = make({alignScenario: 'slow'});
  const r = slow.sim.snapshot().signal.reading, got = collect(slow.sim);
  slow.sim.setControls({quality: 30});
  assert.equal(got.length, 1, 'listeners still hear the control change');
  assert.equal(got[0].signal.reading, r);
});

test('stale freezes seq and collectedAt; changed reports PCI 142; detached has no signal', () => {
  const {c, sim, run} = make();
  run(5000);
  sim.setControls({scenario: 'stale'});
  const s0 = sim.snapshot();
  run(10000);
  const s1 = sim.snapshot();
  assert.equal(s1.connected, false); assert.equal(s1.stale, true);
  assert.equal(s1.signal.seq, s0.signal.seq);
  assert.equal(s1.collectedAt, s0.collectedAt);
  assert.ok(c.t - s1.collectedAt >= 10000);
  sim.setControls({scenario: 'changed'});
  const s2 = sim.snapshot();
  assert.equal(s2.cell.pci, 142);
  assert.equal(s2.connected, true);
  assert.ok(s2.signal.seq > s1.signal.seq);
  assert.ok(s2.quality, 'a fresh cell reports quality on its first reading');
  sim.setControls({scenario: 'searching'});
  const s3 = sim.snapshot();
  assert.equal(s3.attached, false); assert.equal(s3.signal, null); assert.equal(s3.connected, false);
  run(5000);
  assert.equal(sim.snapshot().signal, null);
  sim.setControls({paused: true, scenario: 'connected'});
  const s4 = sim.snapshot();
  assert.equal(s4.paused, true); assert.equal(s4.connected, true);
});

test('auto mode schedules with timers and stops cleanly', async () => {
  const sim = new AlignSim({seed: 1});
  sim.setControls({alignScenario: 'fast'});
  const out = collect(sim);
  sim.start();
  assert.equal(out.length, 1);
  await new Promise(r => setTimeout(r, 1150));
  sim.stop();
  const n = out.length;
  assert.ok(n >= 2);
  await new Promise(r => setTimeout(r, 1100));
  assert.equal(out.length, n);
});
