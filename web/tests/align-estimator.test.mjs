import test from 'node:test';
import assert from 'node:assert/strict';
import {PROFILES, LIMITS, powerMean, combine, LevelFilter, Cadence, SignalEstimator, CellTracker} from '../src/align/estimator.js';

const near = (a, b, tol, msg) => assert.ok(Math.abs(a - b) <= tol, `${msg ?? ''} expected ${b} ±${tol}, got ${a}`);

// Deterministic noise so failures reproduce.
function rng(seed = 7) {
  let s = seed >>> 0;
  return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32);
}
function gauss(r) {
  return Math.sqrt(-2 * Math.log(r() || 1e-12)) * Math.cos(2 * Math.PI * r());
}
const q = (v, step) => Math.round(v / step) * step;

function snap({seq = 1, reading = seq, t = 0, readingT = t, rsrp = [-84.2, -85.1], rsrq = [-9.1, -9.4], heartbeat = false,
  quality = null, pci = 190, eci = 2616332, attached = true, connected = true, paused = false, activeChains = 2} = {}) {
  return {kind: 'demo', receivedAt: t, collectedAt: t, connected, attached, stale: false, paused,
    cell: {pci, earfcn: 56040, band: '48', enbId: 10220, cellId: 12, tac: 10, eci},
    signal: {seq, reading, t, readingT, rsrp, rsrq, rssi: [], heartbeat, source: 'sim', periodMs: 250},
    quality, activeChains, neighbours: [], carriers: [], radio: {}, throughput: {dlBps: null, ulBps: null},
    sas: {grant: 'Authorized', registration: 'Registered'}, gps: null, refresh: null};
}
const qual = (seq, t, cinr = [18.6, 18.6], sinr = 19) => ({seq, t, cinr, sinr, sinrStep: 1, source: 'sim'});

test('powerMean', () => {
  near(powerMean([-99.6, -107.0]), -101.88, 0.01);
  near(powerMean([18.2, 16.1]), 17.28, 0.01);
  assert.equal(powerMean([]), null);
  assert.equal(powerMean([null, NaN]), null);
  assert.equal(powerMean(null), null);
  near(powerMean([-90, null]), -90, 1e-9);
});

test('combine: linear power weighting, sd floor and R', () => {
  assert.equal(combine([]), null);
  assert.equal(combine([{value: null, sd: 1}]), null);
  const eq = combine([{value: -90, sd: 0.4, R: 0.2}, {value: -90, sd: 0.4, R: 0.2}]);
  near(eq.value, -90, 1e-9);
  near(eq.sd, 0.4 / Math.SQRT2, 1e-9);
  near(eq.R, 0.1, 1e-9);
  // A chain 10 dB down carries ~9% of the power, so its noise barely matters.
  const lop = combine([{value: -90, sd: 0.3}, {value: -100, sd: 5}]);
  near(lop.value, powerMean([-90, -100]), 1e-9);
  assert.ok(lop.sd < 0.6, `weak chain dominates sd: ${lop.sd}`);
  assert.equal(lop.R, undefined);
  near(combine([{value: 0, sd: 0}], {quantum: 0.1}).sd, 0.1 / Math.sqrt(12), 1e-12);
});

test('LevelFilter steady-state gain with frozen R', () => {
  const f = new LevelFilter({...PROFILES.rsrp, r0: 0.25, rMin: 0.25, rMax: 0.25});
  let s;
  for (let i = 0; i < 60; i++) s = f.update(0, i * 6000);
  assert.equal(s.mode, 'settled');
  near(s.R, 0.25, 1e-12);
  near(f.P, 0.073, 0.005, 'P');
  near(s.sd, 0.270, 0.005, 'sd');
  const Pm = f.P + PROFILES.rsrp.qS * 6;
  near(Pm, 0.103, 0.005, 'P-');
  near(Pm / (Pm + 0.25), 0.292, 0.005, 'K');
  near(s.hi - s.lo, 2 * 1.96 * s.sd, 1e-9);
});

test('LevelFilter step response and resettle', () => {
  const f = new LevelFilter(PROFILES.rsrp);
  for (let i = 0; i < 5; i++) f.update(-90, i * 2000);
  assert.equal(f.state().mode, 'settled');
  const before = f.state().value;
  const s = f.update(-84, 10000);
  assert.equal(s.mode, 'moving');
  assert.ok(s.value - before >= 5.5, `moved ${s.value - before}`);
  f.update(-84, 12000);
  assert.equal(f.update(-84, 14000).mode, 'settled');
});

test('LevelFilter R floor and ceiling', () => {
  const p = PROFILES.rsrp, f = new LevelFilter(p);
  for (let i = 0; i < 40; i++) {
    const s = f.update(-90, i * 2500);
    if (s.mode === 'settled') assert.ok(s.R >= p.q ** 2 / 12 + p.rMin - 1e-12);
  }
  assert.ok(f.R < 0.03, `identical readings shrink R toward the floor: ${f.R}`);
  const g = new LevelFilter(p), r = rng(3);
  for (let i = 0; i < 200; i++) assert.ok(g.update(-90 + 8 * gauss(r), i * 2500).R <= p.rMax);
});

test('LevelFilter revision replaces the previous update', () => {
  for (const history of [[], [-90, -90.2, -89.9, -90.1]]) {
    const a = new LevelFilter(PROFILES.rsrp), b = new LevelFilter(PROFILES.rsrp);
    history.forEach((y, i) => { a.update(y, i * 2000); b.update(y, i * 2000); });
    const t = history.length * 2000;
    a.update(-95, t);
    const ra = a.update(-91, t + 400, {revise: true});
    const rb = b.update(-91, t + 400);
    assert.deepEqual(ra, rb);
    // A second revision is still relative to the state before the reading.
    const c = new LevelFilter(PROFILES.rsrp);
    history.forEach((y, i) => c.update(y, i * 2000));
    assert.deepEqual(a.update(-92, t + 800, {revise: true}), c.update(-92, t + 800));
  }
});

test('LevelFilter ignores non-finite input and weight < 1 does not count', () => {
  const f = new LevelFilter(PROFILES.rsrp);
  assert.equal(f.update(NaN, 0).value, null);
  f.update(-90, 0);
  f.update(-90, 15000, {weight: 0.5});
  assert.equal(f.state().n, 1);
  assert.equal(f.update(null, 20000).n, 1);
});

test('LevelFilter Huber limits a moderate outlier on CINR while settled', () => {
  const run = (profile) => {
    const f = new LevelFilter(profile), r = rng(11);
    for (let i = 0; i < 30; i++) f.update(q(18 + 0.5 * gauss(r), 0.1), i * 8000);
    assert.equal(f.mode, 'settled');
    const x0 = f.x, z = 2.6, y = x0 + z * Math.sqrt(f.P + profile.qS * 8 + f.R);
    const s = f.update(y, 30 * 8000);
    return {shift: s.value - x0, mode: s.mode};
  };
  const huber = run(PROFILES.cinr), plain = run({...PROFILES.cinr, huber: Infinity});
  assert.equal(huber.mode, 'settled');
  assert.ok(huber.shift > 0 && huber.shift < plain.shift * 0.95, `huber ${huber.shift} vs plain ${plain.shift}`);
});

test('LevelFilter rejects a single gross outlier quickly', () => {
  const f = new LevelFilter(PROFILES.rsrp), r = rng(5);
  for (let i = 0; i < 20; i++) f.update(q(-90 + 0.4 * gauss(r), 0.1), i * 2500);
  f.update(-70, 20 * 2500);
  assert.equal(f.mode, 'moving');
  for (let i = 21; i < 26; i++) f.update(q(-90 + 0.4 * gauss(r), 0.1), i * 2500);
  near(f.x, -90, 1.0, 'recovers after the spike');
  assert.equal(f.mode, 'settled');
});

test('LevelFilter with integer (quantized) SINR', () => {
  const f = new LevelFilter(PROFILES.sinr), r = rng(9);
  for (let i = 0; i < 40; i++) f.update(Math.round(18.5 + 0.4 * gauss(r)), i * 8300);
  const s = f.state();
  near(s.value, 18.5, 0.5);
  assert.ok(s.sd >= 1 / Math.sqrt(12) - 1e-12, 'sd never below quantum resolution');
  assert.ok(s.R >= 1 / 12 + PROFILES.sinr.rMin - 1e-12);
  assert.equal(f.settled(40 * 8300), true, 'alternating 18/19 counts as still');
});

test('LevelFilter settled detection: needs readings, freshness and a tight window', () => {
  const f = new LevelFilter(PROFILES.rsrp);
  f.update(-90, 0);
  f.update(-90.1, 2000);
  assert.equal(f.settled(2000), false);
  f.update(-90, 4000);
  assert.equal(f.mode, 'settled');
  assert.equal(f.settled(4000), true);
  assert.equal(f.settled(4000 + LIMITS.oldMs + 1), false, 'too old');
  f.update(-84, 6000);
  assert.equal(f.settled(6000), false);
});

test('LevelFilter CUSUM catches a slow drift that no single z flags', () => {
  const f = new LevelFilter(PROFILES.rsrp);
  for (let i = 0; i < 10; i++) f.update(q(-90 + (i % 2 ? 0.1 : -0.1), 0.1), i * 2000);
  let sawMoving = false, t = 20000, y = -90;
  for (let i = 0; i < 40 && !sawMoving; i++) {
    y += 0.15; t += 2000;
    const z = (y - f.x) / Math.sqrt(f.P + PROFILES.rsrp.qS * 2 + f.R);
    assert.ok(Math.abs(z) < LIMITS.zSettle, `z ${z}`);
    if (f.update(y, t).mode === 'moving') sawMoving = true;
  }
  assert.ok(sawMoving);
});

test('LevelFilter irregular cadence stays stable', () => {
  const f = new LevelFilter(PROFILES.rsrp), r = rng(21);
  let t = 0;
  for (let i = 0; i < 300; i++) {
    t += 100 + r() * 9900;
    const s = f.update(q(-95 + 0.5 * gauss(r), 0.1), t);
    assert.ok(Number.isFinite(s.value) && s.sd > 0);
  }
  near(f.x, -95, 0.8);
  assert.ok(f.R > 0.05 && f.R < 1.5, `learned R ${f.R}`);
});

test('Cadence expectation, eta and overdue', () => {
  const c = new Cadence({initialMs: 2500, priorMs: [1000, 2500, 4000, 6000]});
  assert.equal(c.expected, 2500);
  assert.deepEqual(c.eta(0), {p50: null, p90: null, overdue: false});
  let t = 10000;
  c.observe(t);
  // Prior gaps while fewer than five are known.
  assert.deepEqual(c.eta(t + 500), {p50: 2750, p90: 4900, overdue: false});
  for (const g of [2000, 2500, 3000, 2600, 2400]) c.observe((t += g));
  const S = [1000, 1500, 2000, 1600, 1400];
  assert.equal(c.eta(t + 1000).p50, 1500);
  near(c.eta(t + 1000).p90, 1840, 1e-9);
  assert.deepEqual(S.sort((a, b) => a - b)[2], 1500);
  assert.deepEqual(c.eta(t + 3500), {p50: null, p90: null, overdue: true});
  let e = 2500;
  for (const g of [2000, 2500, 3000, 2600, 2400]) e = 0.3 * g + 0.7 * e;
  near(c.expected, e, 1e-9);
  c.observe(t + 100); // burst revision gap, rejected
  c.observe(t + 100 + 40000); // detach-sized gap, rejected
  near(c.expected, e, 1e-9);
  assert.equal(c.gaps.length, 5);
  c.reset();
  assert.equal(c.expected, 2500);
  assert.equal(c.eta(1e9).p50, null);
});

test('Cadence adapts from slow to a 1 Hz source and clamps', () => {
  const c = new Cadence({initialMs: 2500, priorMs: [1000]});
  let t = 0;
  for (let i = 0; i < 40; i++) c.observe((t += 1000));
  near(c.expected, 1000, 5);
  for (let i = 0; i < 40; i++) c.observe((t += 25000));
  assert.equal(c.expected, 20000);
});

test('SignalEstimator: seq gating, revisions, heartbeats', () => {
  const e = new SignalEstimator();
  let ev = e.ingest(snap({seq: 1, reading: 1, t: 1000}), 1000);
  assert.deepEqual(ev, {signal: 'new', quality: null, reset: null});
  assert.equal(e.state.signal.n, 1);
  ev = e.ingest(snap({seq: 1, reading: 1, t: 1000, rsrp: [-70, -70]}), 2000);
  assert.deepEqual(ev, {signal: null, quality: null, reset: null});
  near(e.state.signal.raw, powerMean([-84.2, -85.1]), 1e-9, 'same seq ignored even with other values');
  ev = e.ingest(snap({seq: 2, reading: 1, t: 1400, readingT: 1000, rsrp: [-84.0, -85.0]}), 2000);
  assert.equal(ev.signal, 'revised');
  assert.equal(e.state.signal.n, 1);
  assert.equal(e.state.readings.length, 1);
  near(e.state.readings[0].raw, powerMean([-84.0, -85.0]), 1e-9);
  ev = e.ingest(snap({seq: 3, reading: 2, t: 3500, rsrp: [-84.1, -85.0]}), 3600);
  assert.equal(ev.signal, 'new');
  assert.equal(e.state.signal.n, 2);
  ev = e.ingest(snap({seq: 4, reading: 3, t: 18600, rsrp: [-84.1, -85.0], heartbeat: true}), 18700);
  assert.equal(ev.signal, 'heartbeat');
  assert.equal(e.state.signal.n, 2, 'heartbeat never counts');
  assert.equal(e.state.signal.heartbeat, true);
  assert.equal(e.state.signal.t, 18600, 'heartbeat ages the reading');
  assert.equal(e.state.readings.length, 2, 'heartbeat is not a reading');
  const before = e.cadenceS.expected;
  e.ingest(snap({seq: 5, reading: 4, t: 33600, rsrp: [-84.1, -85.0], heartbeat: true}), 33700);
  assert.equal(e.cadenceS.expected, before, 'heartbeat gaps never stretch the cadence');
  ev = e.ingest(snap({seq: 6, reading: 5, t: 36000, rsrp: [-84.3, -85.0]}), 36000);
  assert.equal(ev.reset, null, 'heartbeats keep the gap timer alive');
  assert.equal(e.state.signal.n, 3);
});

test('LevelFilter: revision only undoes the same reading; bad timestamps are ignored', () => {
  const f = new LevelFilter(PROFILES.rsrp);
  for (let i = 1; i <= 3; i++) f.update(-95, i * 1000, {key: i});
  f.update(-80, 4000, {revise: true, key: 4});
  assert.equal(f.n, 4, 'a chain first seen on a revision is a new reading');
  const g = new LevelFilter(PROFILES.rsrp);
  g.update(-90, 0); g.update(-90.2, 1000); g.update(-90.1, NaN); g.update(-90, 3000);
  assert.ok(Number.isFinite(g.state().value) && Number.isFinite(g.state().sd));
});

test('LevelFilter: reported R is not biased high on stationary noise', () => {
  let s = 11;
  const rnd = () => { s = (s * 16807) % 2147483647; return s / 2147483647; };
  const g = () => Math.sqrt(-2 * Math.log(rnd())) * Math.cos(2 * Math.PI * rnd());
  const Rs = [];
  for (let k = 0; k < 60; k++) {
    const f = new LevelFilter(PROFILES.rsrp);
    for (let i = 0; i < 200; i++) f.update(Math.round((-90 + g()) * 10) / 10, i * 2500);
    Rs.push(f.state().R);
  }
  near(Rs.reduce((a, b) => a + b, 0) / Rs.length, 1, 0.2);
});

test('SignalEstimator: raw, best, imbalance and filtered imbalance', () => {
  const e = new SignalEstimator();
  for (let i = 1; i <= 6; i++) e.ingest(snap({seq: i, t: i * 2000, rsrp: [-99.6, -106.2]}), i * 2000);
  const s = e.state.signal;
  near(s.raw, powerMean([-99.6, -106.2]), 1e-9);
  assert.equal(s.best, -99.6);
  near(s.imbalance, 6.6, 1e-9);
  near(s.imbalanceEst, 6.6, 0.05);
  assert.deepEqual(s.chains, [-99.6, -106.2]);
  near(s.est, s.raw, 0.05);
  assert.ok(s.lo < s.est && s.est < s.hi);
  assert.equal(s.settled, true);
  assert.equal(s.mode, 'settled');
  near(e.state.rsrq.raw, -9.25, 1e-9);
  // One chain missing: still estimated from the other, imbalance unknown.
  e.ingest(snap({seq: 7, t: 14000, rsrp: [-99.6, null]}), 14000);
  assert.equal(e.state.signal.imbalance, null);
  near(e.state.signal.raw, -99.6, 1e-9);
});

test('SignalEstimator: single active chain ignores the second value', () => {
  const e = new SignalEstimator();
  e.ingest(snap({seq: 1, t: 0, rsrp: [-90, -80], activeChains: 1}), 0);
  near(e.state.signal.est, -90, 1e-9);
  assert.equal(e.state.signal.imbalanceEst, null);
});

test('CellTracker: late or blank ECI is never a cell change', () => {
  const c = new CellTracker();
  assert.equal(c.offer(190, 2616332, 0), false);
  assert.equal(c.offer(190, null, 1000), false, 'blank ECI during attach');
  assert.equal(c.offer(190, 2616332, 2000), false);
  assert.equal(c.offer(211, 2616332, 20000), true, 'PCI change counts once');
  assert.equal(c.offer(211, 99, 26000), false, 'ECI catching up after a handover');
  assert.equal(c.offer(211, 98, 40000), true, 'a settled ECI change is a new cell');
  assert.equal(c.offer(null, null, 41000), false);
});

test('SignalEstimator: cell change, gap and detach resets', () => {
  const e = new SignalEstimator();
  for (let i = 1; i <= 4; i++) e.ingest(snap({seq: i, t: i * 2000}), i * 2000);
  assert.equal(e.state.signal.n, 4);
  let ev = e.ingest(snap({seq: 5, t: 10000, pci: 211, eci: 99}), 10000);
  assert.equal(ev.reset, 'cell');
  assert.equal(ev.signal, 'new');
  assert.equal(e.state.signal.n, 1, 'the first reading on the new cell counts');
  assert.equal(e.state.readings.length, 1);
  assert.equal(e.state.resets, 1);
  near(e.state.cadence.signalMs, e.cadenceS.expected, 0);
  assert.notEqual(e.state.cadence.signalMs, 2500, 'cadence kept on cell change');

  ev = e.ingest(snap({seq: 6, t: 41500, pci: 211, eci: 99}), 41500);
  assert.equal(ev.reset, 'gap');
  assert.equal(e.state.signal.n, 1);
  assert.equal(e.state.signal.delta, null);

  ev = e.ingest(snap({seq: 7, t: 43000, pci: 211, eci: 99, attached: false, connected: false}), 43000);
  assert.deepEqual(ev, {signal: null, quality: null, reset: 'detach'});
  assert.equal(e.state.signal.n, 0);
  assert.equal(e.state.freshness, 'none');
  assert.equal(e.state.cadence.signalMs, 2500, 'cadence cleared on detach');
  ev = e.ingest(snap({seq: 8, t: 44000, attached: false, connected: false}), 44000);
  assert.equal(ev.reset, null, 'detach resets once');
  ev = e.ingest(snap({seq: 9, t: 45000, pci: 300}), 45000);
  assert.equal(ev.reset, null, 'reattach on another cell is not a second reset');
  assert.equal(ev.signal, 'new');
  assert.equal(e.state.resets, 3);
});

test('SignalEstimator: paused snapshots are not consumed', () => {
  const e = new SignalEstimator();
  e.ingest(snap({seq: 1, t: 0}), 0);
  const ev = e.ingest(snap({seq: 2, reading: 2, t: 2000, paused: true, rsrp: [-70, -70]}), 2000);
  assert.deepEqual(ev, {signal: null, quality: null, reset: null});
  assert.equal(e.state.signal.seq, 1);
  assert.equal(e.state.t, 2000);
  assert.equal(e.ingest(snap({seq: 2, reading: 2, t: 2000, rsrp: [-70, -70]}), 2500).signal, 'new', 'consumed after unpause');
});

test('SignalEstimator: quality from CINR, switch to SINR, trend', () => {
  const e = new SignalEstimator();
  let ev = e.ingest(snap({seq: 1, t: 0, quality: qual(1, 0, [18.6, 18.6])}), 0);
  assert.equal(ev.quality, 'new');
  let s = e.state.quality;
  assert.equal(s.source, 'cinr');
  near(s.raw, 18.6, 1e-9);
  near(s.est, 18.6, 1e-9);
  assert.equal(s.step, 0.1);
  assert.equal(s.sinr, 19);
  assert.equal(s.n, 1);
  assert.equal(e.ingest(snap({seq: 1, t: 0, quality: qual(1, 0, [10, 10])}), 1000).quality, null);
  e.ingest(snap({seq: 2, t: 8000, quality: qual(2, 8000, [21.0, 20.6])}), 8000);
  s = e.state.quality;
  assert.equal(s.trend, 'up');
  near(s.delta, powerMean([21.0, 20.6]) - 18.6, 1e-9);
  e.ingest(snap({seq: 3, t: 16000, quality: qual(3, 16000, [21.2, 20.6])}), 16000);
  assert.equal(e.state.quality.trend, 'steady');
  ev = e.ingest(snap({seq: 4, t: 24000, quality: qual(4, 24000, null, 17)}), 24000);
  s = e.state.quality;
  assert.equal(ev.quality, 'new');
  assert.equal(s.source, 'sinr');
  assert.equal(s.est, 17, 'filters reset on source switch');
  assert.equal(s.delta, null, 'no trend across sources');
  assert.equal(s.step, 1);
  assert.ok(s.sd >= 1 / Math.sqrt(12) - 1e-12);
  assert.equal(e.state.readings.at(-1).quality, powerMean([21.2, 20.6]), 'readings carry the latest quality');
});

test('SignalEstimator: signal trend and deadband', () => {
  const e = new SignalEstimator();
  e.ingest(snap({seq: 1, t: 0, rsrp: [-90, -90]}), 0);
  const s0 = e.state.signal;
  near(s0.deadband, Math.min(3, Math.max(0.5, 2 * Math.sqrt(2 * s0.R))), 1e-12);
  near(s0.R, 0.5 * PROFILES.rsrp.r0, 1e-12, 'two equal chains at r0');
  assert.equal(s0.trend, null);
  e.ingest(snap({seq: 2, t: 2000, rsrp: [-88, -88]}), 2000);
  assert.equal(e.state.signal.trend, 'up');
  near(e.state.signal.delta, 2, 1e-9);
  e.ingest(snap({seq: 3, t: 4000, rsrp: [-88.3, -88.3]}), 4000);
  assert.equal(e.state.signal.trend, 'steady');
  e.ingest(snap({seq: 4, t: 6000, rsrp: [-92, -92]}), 6000);
  assert.equal(e.state.signal.trend, 'down');
  // A revision recomputes delta against the previous reading, not the revised sample.
  e.ingest(snap({seq: 5, reading: 4, t: 6400, readingT: 6000, rsrp: [-88.2, -88.2]}), 6400);
  assert.equal(e.state.signal.trend, 'steady');
  near(e.state.signal.delta, 0.1, 1e-9);
  assert.equal(new SignalEstimator().state.signal.deadband, Math.min(3, Math.max(0.5, 2 * Math.sqrt(2 * PROFILES.rsrp.r0))));
});

test('SignalEstimator: freshness live, waiting, old, none', () => {
  const e = new SignalEstimator();
  assert.equal(e.state.freshness, 'none');
  const s = snap({seq: 1, t: 1000});
  e.ingest(s, 1000);
  const E = e.state.cadence.signalMs;
  assert.equal(E, 2500);
  assert.equal(e.ingest(s, 1000 + 2 * E).signal, null);
  assert.equal(e.state.freshness, 'live');
  e.ingest(s, 1001 + 2 * E);
  assert.equal(e.state.freshness, 'waiting');
  assert.equal(e.stateAt(1000 + LIMITS.oldMs).freshness, 'waiting');
  assert.equal(e.stateAt(1001 + LIMITS.oldMs).freshness, 'old');
  assert.equal(e.stateAt(1000 + LIMITS.noneMs).freshness, 'old');
  assert.equal(e.stateAt(1001 + LIMITS.noneMs).freshness, 'none');
  assert.equal(e.state.t, 1001 + LIMITS.noneMs);
  assert.equal(e.state.signal.ageMs, LIMITS.noneMs + 1);
  e.ingest({...s, connected: false}, 1100);
  assert.equal(e.state.freshness, 'none');
});

test('SignalEstimator: poll independence', () => {
  const e = new SignalEstimator();
  for (let i = 1; i <= 5; i++) e.ingest(snap({seq: i, t: i * 2500, rsrp: [-84 - i * 0.1, -85], quality: qual(1, 2500)}), i * 2500);
  const pick = (st) => ({signal: {...st.signal, ageMs: 0, settled: 0}, quality: {...st.quality, ageMs: 0, settled: 0},
    rsrq: st.rsrq, readings: st.readings, resets: st.resets, signalMs: st.cadence.signalMs, qualityMs: st.cadence.qualityMs});
  const ref = pick(e.state);
  const same = snap({seq: 5, t: 12500, rsrp: [-84.5, -85], quality: qual(1, 2500)});
  for (let now = 12500; now < 60000; now += 1000) {
    assert.deepEqual(e.ingest(same, now), {signal: null, quality: null, reset: null});
    assert.deepEqual(pick(e.state), ref);
  }
});

test('SignalEstimator: irregular burst cadence and outliers end to end', () => {
  const e = new SignalEstimator(), r = rng(42);
  let t = 0, seq = 0, reading = 0, qseq = 0, nextQ = 8000, events = 0;
  for (let k = 0; k < 60; k++) {
    t += 600 + r() * 5000;
    reading++;
    const readingT = t;
    const burst = 1 + Math.floor(r() * 3);
    for (let b = 0; b < burst; b++) {
      seq++;
      const spike = k === 30 && b === 0 ? -15 : 0;
      const rsrp = [q(-92 + 0.5 * gauss(r) + spike, 0.1), q(-95 + 0.5 * gauss(r) + spike, 0.1)];
      let quality = qseq ? qual(qseq, nextQ - 8300) : null;
      if (t >= nextQ) { qseq++; quality = qual(qseq, t, [q(17 + 0.4 * gauss(r), 0.1), q(16 + 0.4 * gauss(r), 0.1)]); nextQ = t + 8300; }
      const ev = e.ingest(snap({seq, reading, t: t + b * 400, readingT, rsrp, quality}), t + b * 400 + 200);
      if (ev.signal === 'new') events++;
      // The 1 s poll repeats the same snapshot.
      assert.equal(e.ingest(snap({seq, reading, t: t + b * 400, readingT, rsrp, quality}), t + b * 400 + 1200).signal, null);
    }
    t += (burst - 1) * 400;
  }
  const s = e.state;
  assert.equal(events, 60);
  assert.equal(s.signal.n, 60);
  assert.equal(s.readings.length, 60);
  near(s.signal.est, powerMean([-92, -95]), 0.8);
  near(s.signal.imbalanceEst, 3, 1.0);
  near(s.quality.est, powerMean([17, 16]), 0.8);
  assert.ok(s.cadence.signalMs > 1000 && s.cadence.signalMs < 6000, `cadence ${s.cadence.signalMs}`);
  assert.ok(s.cadence.qualityMs > 7000 && s.cadence.qualityMs < 10000, `quality cadence ${s.cadence.qualityMs}`);
  assert.ok(s.signal.R > 0.02 && s.signal.R < 1, `R ${s.signal.R}`);
});

test('SignalEstimator: readings ring keeps the last 120', () => {
  const e = new SignalEstimator();
  for (let i = 1; i <= 130; i++) e.ingest(snap({seq: i, t: i * 1000}), i * 1000);
  const rs = e.state.readings;
  assert.equal(rs.length, 120);
  assert.equal(rs[0].reading, 11);
  assert.equal(rs.at(-1).reading, 130);
  rs[0].chains.push(1);
  assert.equal(e.state.readings[0].chains.length, 2, 'state is a copy');
});

test('SignalEstimator: manual reset and null snapshot', () => {
  const e = new SignalEstimator();
  assert.deepEqual(e.ingest(null, 5), {signal: null, quality: null, reset: null});
  e.ingest(snap({seq: 1, t: 0}), 0);
  e.reset('manual');
  assert.equal(e.state.signal.est, null);
  assert.equal(e.state.signal.mode, null);
  assert.equal(e.state.resets, 1);
  assert.equal(e.ingest(snap({seq: 1, t: 0}), 100).signal, null, 'pre-reset sample is not consumed again');
  assert.equal(e.ingest(snap({seq: 2, reading: 1, t: 400}), 500).signal, 'new', 'first sample after reset starts a reading');
});
