import test from 'node:test';
import assert from 'node:assert/strict';
import {NF_RE_DBM, THRESHOLDS, derive, evaluate, Diagnostics, grade, acceptance, earfcnMhz, pick, sortFindings} from '../src/align/diagnostics.js';

const powerMean = (xs) => 10 * Math.log10(xs.reduce((a, x) => a + 10 ** (x / 10), 0) / xs.length);
const near = (a, b, eps = 0.02) => assert.ok(Math.abs(a - b) <= eps, `${a} != ${b}`);

// Section 2.2 bench values: PCC EARFCN 56040, PCI 190.
function benchSnapshot(over = {}) {
  return {
    kind: 'device', receivedAt: 1000, collectedAt: 1000, connected: true, attached: true, stale: false, paused: false,
    cell: {pci: 190, earfcn: 56040, band: '48', enbId: 10220, cellId: 12, tac: 10, eci: 2616332},
    signal: {seq: 5, reading: 3, t: 900, readingT: 800, rsrp: [-99.6, -106.3], rsrq: [-5.8, -6.2], rssi: [-73.8, -80.1], heartbeat: false, source: 'watch', periodMs: 250},
    quality: {seq: 2, t: 500, cinr: [18.3, 16.5], sinr: 18, sinrStep: 1, source: 'watch'},
    activeChains: 2,
    neighbours: [
      {earfcn: 56040, pci: 189, rsrp: -114, rsrq: -21, rssi: -73, coChannel: 'pcc'},
      {earfcn: 56638, pci: 217, rsrp: -110, rsrq: -7, rssi: -83, coChannel: 'scc1'},
      {earfcn: 56638, pci: 216, rsrp: -119, rsrq: -15, rssi: -84, coChannel: 'scc1'},
      {earfcn: 56440, pci: 208, rsrp: -108, rsrq: -7, rssi: -81, coChannel: null},
      {earfcn: 56440, pci: 207, rsrp: -117, rsrq: -15, rssi: -81, coChannel: null},
    ],
    carriers: [],
    radio: {cqi: null, ri: null, dlModulation: null, dlMcs: null, ulModulation: null, ulMcs: null, configured: 1, active: 1, txPowerDbm: 2, mimo: 'TM4'},
    throughput: {dlBps: null, ulBps: null},
    sas: {grant: 'Authorized', registration: 'Registered'},
    gps: null, refresh: null,
    ...over,
  };
}

function estimateFor(chains = [-99.6, -106.3], cinr = [18.3, 16.5], over = {}) {
  const raw = powerMean(chains), q = cinr ? powerMean(cinr) : null;
  const readings = [0, 1, 2, 3, 4].map((i) => ({reading: i + 1, t: i * 2500, raw, chains, est: raw, sd: 0.3, quality: q}));
  const {signal = {}, quality = {}, ...rest} = over;
  return {
    t: 10000, freshness: 'live',
    signal: {seq: 5, reading: 5, t: 9000, readingT: 9000, ageMs: 1000, raw, chains, best: Math.max(...chains), imbalance: chains[0] - chains[1],
      imbalanceEst: null, est: raw, sd: 0.3, lo: raw - 0.6, hi: raw + 0.6, R: 0.25, mode: 'settled', settled: true,
      trend: 'steady', delta: 0, deadband: 1, n: 5, heartbeat: false, ...signal},
    quality: {seq: 2, t: 5000, ageMs: 5000, source: 'cinr', step: 0.1, raw: q, chains: cinr ?? [], sinr: 18, est: q, sd: 0.4, lo: null, hi: null, R: 0.5,
      mode: 'settled', settled: true, trend: 'steady', delta: 0, deadband: 1, n: 2, ...quality},
    rsrq: {raw: -6, est: -6, sd: 0.2},
    cadence: {signalMs: 2500, qualityMs: 8300, signalEta: {p50: null, p90: null, overdue: false}, qualityEta: {p50: null, p90: null, overdue: false}},
    readings, resets: 0, ...rest,
  };
}

const balanced = () => estimateFor([-92, -93.5]);
const ctxOf = (over = {}) => ({now: 10000, estimate: estimateFor(), snapshot: benchSnapshot(), positions: [], peak: null, capturing: false, bearing: null, dlPeakBps: null, final: null, ...over});
const ids = (list) => list.map((f) => f.id);

test('derive on the bench snapshot', () => {
  const d = derive(ctxOf());
  near(d.margin.db, 14.4, 1e-9);
  assert.equal(d.margin.pci, 189);
  assert.equal(d.margin.sameGroup, true);
  assert.equal(d.margin.mod3, false);
  assert.equal(d.margin.clash, false);
  near(d.quality, 17.49, 0.01);
  near(d.deficit, Math.min(-99.6 - NF_RE_DBM, 30) - d.quality, 1e-9);
  near(d.deficit, 7.91, 0.01);
  near(d.loadGap, (-73.8 - 80.1) / 2 - (-99.6 - 106.3) / 2, 1e-9);
  near(d.imbalance, 6.7, 1e-9);
  assert.equal(d.sdSignal, 0);
  assert.equal(d.steady, true);
});

test('derive: missing inputs give nulls, not guesses', () => {
  const d = derive(ctxOf({snapshot: benchSnapshot({neighbours: [], signal: null}), estimate: estimateFor([-99.6, -106.3], null, {readings: []})}));
  assert.equal(d.margin, null);
  assert.equal(d.loadGap, null);
  assert.equal(d.deficit, null);
  assert.equal(d.imbalance, null);
  assert.equal(d.sdSignal, null);
  assert.equal(d.sdQuality, null);
  const clashOnly = derive(ctxOf({snapshot: benchSnapshot({neighbours: [{earfcn: 56040, pci: 190, rsrp: -110, rsrq: null, rssi: null, coChannel: 'pcc'}]})}));
  assert.equal(clashOnly.margin.db, null);
  assert.equal(clashOnly.margin.clash, true);
});

test('derive: mod3 needs a co-channel neighbour within 10 dB with the same PCI mod 3', () => {
  const n = (pci, rsrp) => ({earfcn: 56040, pci, rsrp, rsrq: null, rssi: null, coChannel: 'pcc'});
  assert.equal(derive(ctxOf({snapshot: benchSnapshot({neighbours: [n(193, -105)]})})).margin.mod3, true);
  assert.equal(derive(ctxOf({snapshot: benchSnapshot({neighbours: [n(193, -110)]})})).margin.mod3, false);
  assert.equal(derive(ctxOf({snapshot: benchSnapshot({neighbours: [n(192, -100)]})})).margin.sameGroup, false);
});

test('bench snapshot trips only D6 (6.7 dB imbalance); a strong balanced spot is good', () => {
  assert.deepEqual(ids(evaluate(ctxOf())), ['D6']);
  assert.deepEqual(ids(evaluate(ctxOf({estimate: balanced()}))), ['D13']);
});

test('D1 fires for Granted and Idle, not Unknown or Authorized; D1 suppresses D13', () => {
  for (const g of ['Granted', 'Idle', 'Suspended']) {
    const f = evaluate(ctxOf({snapshot: benchSnapshot({sas: {grant: g, registration: 'Registered'}})}));
    assert.ok(ids(f).includes('D1'), g);
    assert.ok(!ids(f).includes('D13'), g);
    assert.match(f.find((x) => x.id === 'D1').title, new RegExp(`state: ${g}`));
    assert.match(f.find((x) => x.id === 'D1').detail, /Navy radar/);
  }
  for (const g of ['Unknown', 'Authorized']) assert.ok(!ids(evaluate(ctxOf({snapshot: benchSnapshot({sas: {grant: g, registration: 'Unknown'}})}))).includes('D1'), g);
  assert.ok(!ids(evaluate(ctxOf({snapshot: benchSnapshot({sas: {grant: 'Unknown', registration: 'Unknown'}})}))).includes('D13'));
  const d = new Diagnostics();
  const shown = d.update(ctxOf({snapshot: benchSnapshot({sas: {grant: 'Granted', registration: 'Registered'}})}), {newEvidence: false});
  assert.deepEqual(ids(shown), ['D1']);
});

test('D1 radar note only for 3550-3650 MHz', () => {
  assert.equal(earfcnMhz(56040), 3630);
  assert.equal(earfcnMhz(56638), 3689.8);
  const f = evaluate(ctxOf({snapshot: benchSnapshot({cell: {...benchSnapshot().cell, earfcn: 56638}, sas: {grant: 'Idle', registration: 'Registered'}})}));
  assert.equal(f.find((x) => x.id === 'D1').detail, '');
});

test('D2 fires immediately on !attached, stale, freshness none and very weak signal', () => {
  const d = new Diagnostics();
  assert.deepEqual(ids(d.update(ctxOf({snapshot: benchSnapshot({attached: false})}), {newEvidence: false})), ['D2']);
  assert.deepEqual(ids(d.update(ctxOf(), {newEvidence: false})), [], 'clears immediately');
  assert.ok(ids(evaluate(ctxOf({estimate: estimateFor([-99.6, -106.3], [18.3, 16.5], {freshness: 'none'})}))).includes('D2'));
  assert.ok(ids(evaluate(ctxOf({snapshot: benchSnapshot({stale: true})}))).includes('D2'));
  const weak = evaluate(ctxOf({estimate: estimateFor([-121, -123], [1, 1])})).find((f) => f.id === 'D2');
  assert.equal(weak.detail, 'RSRP -121.0 dBm');
  const old = evaluate(ctxOf({estimate: estimateFor(undefined, undefined, {freshness: 'none', signal: {ageMs: 41000}})})).find((f) => f.id === 'D2');
  assert.equal(old.detail, 'No reading for 41 s');
  assert.equal(old.title, 'No new readings from the Titan for 41 s.', 'stale data is a data-path fault');
  assert.match(old.action, /not the antenna/);
  assert.match(evaluate(ctxOf({snapshot: benchSnapshot({attached: false})})).find((f) => f.id === 'D2').action, /sweep slowly/);
  const noGrant = evaluate(ctxOf({snapshot: benchSnapshot({attached: false, sas: {grant: 'Idle', registration: 'Registered'}})}));
  assert.equal(noGrant.find((f) => f.id === 'D2').action, '', 'no sweep advice next to "not an aiming problem"');
  assert.ok(!ids(evaluate(ctxOf({estimate: estimateFor([-119, -121], [1, 1])}))).includes('D2'));
  assert.ok(!ids(evaluate(ctxOf({snapshot: benchSnapshot({paused: true}), estimate: estimateFor(undefined, undefined, {freshness: 'none'})}))).includes('D2'));
  assert.deepEqual(evaluate(ctxOf({snapshot: null})), []);
});

const coNeighbour = (pci, rsrp) => ({earfcn: 56040, pci, rsrp, rsrq: null, rssi: null, coChannel: 'pcc'});

test('D3 margin under 3 dB, with the stronger-cell wording below 0', () => {
  const close = evaluate(ctxOf({snapshot: benchSnapshot({neighbours: [coNeighbour(189, -101)]})})).find((f) => f.id === 'D3');
  assert.equal(close.title, 'Another cell (PCI 189) is nearly as strong.');
  assert.equal(close.detail, 'Margin 1.4 dB · same site: yes');
  const over = evaluate(ctxOf({snapshot: benchSnapshot({neighbours: [coNeighbour(211, -97)]})})).find((f) => f.id === 'D3');
  assert.equal(over.title, 'PCI 211 is stronger than your cell by 2.6 dB.');
  assert.match(over.detail, /same site: no/);
  assert.ok(!ids(evaluate(ctxOf({snapshot: benchSnapshot({neighbours: [coNeighbour(189, -102.6)]})}))).includes('D3'));
});

test('D4 fires on strong signal with poor quality; sub-case order', () => {
  const est = estimateFor([-90, -91], [5, 5]);
  const base = evaluate(ctxOf({estimate: est})).find((f) => f.id === 'D4');
  assert.equal(base.action, 'Try a few degrees either side, then report it.');
  assert.equal(base.detail, 'Quality 5.0 dB · ceiling 30.0 dB');
  // margin < 6 (a) wins over mod3 (b): 193 % 3 === 190 % 3 and within 10 dB.
  const a = evaluate(ctxOf({estimate: est, snapshot: benchSnapshot({neighbours: [coNeighbour(193, -94)]})})).find((f) => f.id === 'D4');
  assert.equal(a.evidence.sub, 'a');
  assert.equal(a.action, 'Turn to favor your sector over PCI 193.');
  const b = evaluate(ctxOf({estimate: est, snapshot: benchSnapshot({neighbours: [coNeighbour(193, -97)]})})).find((f) => f.id === 'D4');
  assert.equal(b.evidence.sub, 'b');
  assert.equal(b.action, 'Re-aim for 10 dB of margin and report PCI 193.');
  const cEst = estimateFor([-90, -91], [5, 5], {rsrq: {raw: -13, est: -13, sd: 0.2}});
  const cSnap = benchSnapshot({signal: {...benchSnapshot().signal, rsrp: [-90, -91], rssi: [-58, -59]}, throughput: {dlBps: 2e5, ulBps: 0}});
  assert.equal(evaluate(ctxOf({estimate: cEst, snapshot: cSnap})).find((f) => f.id === 'D4').evidence.sub, 'c');
  assert.equal(evaluate(ctxOf({estimate: cEst, snapshot: {...cSnap, throughput: {dlBps: null, ulBps: null}}})).find((f) => f.id === 'D4').evidence.sub, 'e', 'missing dlBps does not guess');
  // (d) needs varying quality over steady signal; use Diagnostics-tracked quality history.
  const mem = {quality: [2, 9, 3, 10, 4], txHigh: 0};
  assert.equal(evaluate(ctxOf({estimate: est}), mem).find((f) => f.id === 'D4').evidence.sub, 'd');
  assert.ok(!ids(evaluate(ctxOf({estimate: estimateFor([-96, -97], [5, 5])}))).includes('D4'), 'best below -95');
  assert.ok(!ids(evaluate(ctxOf({estimate: estimateFor([-90, -91], [10.5, 10.5])}))).includes('D4'), 'quality >= 10');
});

test('D5 PCI clash', () => {
  const f = evaluate(ctxOf({snapshot: benchSnapshot({neighbours: [coNeighbour(190, -118)]})})).find((x) => x.id === 'D5');
  assert.equal(f.action, 'Do not accept this install. Report PCI 190 and EARFCN 56040.');
  assert.ok(!ids(evaluate(ctxOf())).includes('D5'));
});

const scc = (rsrpChains) => ({role: 'scc', index: 1, earfcn: 56638, pci: 217, bandwidthMhz: null, sinr: null, rsrpChains, rsrqChains: [], rssiChains: [], cinrChains: [], active: true, dlModulation: null, dlMcs: null});
const pos = (imbalance, deg = null) => ({id: `p${imbalance}`, imbalance, heading: deg === null ? null : {deg, sd: 1, source: 'abs', relative: false}});

test('D6 hardware vs multipath copy', () => {
  const est = estimateFor([-96, -104], [15, 15]);
  const hw = evaluate(ctxOf({estimate: est, snapshot: benchSnapshot({carriers: [scc([-110, -116])]}), positions: [pos(8), pos(7)]})).find((f) => f.id === 'D6');
  assert.equal(hw.title, 'One receive path is weak on every carrier.');
  assert.match(hw.action, /Re-aiming will not fix this/);
  assert.equal(hw.detail, 'RX1 -96.0 / RX2 -104.0 dBm');
  const mp = evaluate(ctxOf({estimate: est, snapshot: benchSnapshot({carriers: [scc([-115, -110])]}), positions: [pos(8), pos(7)]})).find((f) => f.id === 'D6');
  assert.equal(mp.title, 'One antenna path is weaker by 8.0 dB.');
  assert.equal(mp.action, 'Move slightly or clear nearby obstructions.');
  const noScc = evaluate(ctxOf({estimate: est, positions: [pos(8), pos(7)]})).find((f) => f.id === 'D6');
  assert.equal(noScc.evidence.hardware, false, 'no SCC chain data: cannot confirm hardware');
  const closeHeadings = evaluate(ctxOf({estimate: est, snapshot: benchSnapshot({carriers: [scc([-110, -116])]}), positions: [pos(8, 100), pos(7, 110)]})).find((f) => f.id === 'D6');
  assert.equal(closeHeadings.evidence.hardware, false, 'positions under 15 degrees apart');
  const wide = evaluate(ctxOf({estimate: est, snapshot: benchSnapshot({carriers: [scc([-110, -116])]}), positions: [pos(8, 355), pos(7, 20)]})).find((f) => f.id === 'D6');
  assert.equal(wide.evidence.hardware, true);
  const big = evaluate(ctxOf({estimate: estimateFor([-96, -108], [15, 15])})).find((f) => f.id === 'D6');
  assert.equal(big.severity, 'warn');
  assert.match(big.title, /\(one stream likely\)$/);
  assert.ok(!ids(evaluate(ctxOf({estimate: estimateFor([-96, -102], [15, 15])}))).includes('D6'), '6 dB is not > 6');
});

test('D6 uses the median of the last 3 readings', () => {
  const est = estimateFor([-96, -104], [15, 15]);
  est.readings = est.readings.map((r, i) => ({...r, chains: i === 4 ? [-96, -97] : r.chains}));
  assert.ok(ids(evaluate(ctxOf({estimate: est}))).includes('D6'));
  est.readings[3] = {...est.readings[3], chains: [-96, -97]};
  assert.ok(!ids(evaluate(ctxOf({estimate: est}))).includes('D6'));
});

test('D7 weak but clean', () => {
  const f = evaluate(ctxOf({estimate: estimateFor([-108, -109], [15, 15])})).find((x) => x.id === 'D7');
  assert.equal(f.detail, 'RSRP -108.0 dBm');
  assert.ok(!ids(evaluate(ctxOf({estimate: estimateFor([-108, -109], [10, 10])}))).includes('D7'), 'deficit >= 6');
  assert.ok(!ids(evaluate(ctxOf({estimate: estimateFor([-104, -105], [19, 19])}))).includes('D7'));
});

test('D8 side lobe: far below peak, narrow fit, or same signal with much worse quality', () => {
  const sig = powerMean([-99.6, -106.3]), q = powerMean([18.3, 16.5]);
  const far = evaluate(ctxOf({peak: {value: sig + 11, heading: null, quality: null}})).find((f) => f.id === 'D8');
  assert.equal(far.detail, '11.0 dB below the peak');
  const notSteady = estimateFor(undefined, undefined, {signal: {settled: false}});
  assert.ok(!ids(evaluate(ctxOf({estimate: notSteady, peak: {value: sig + 11, heading: null, quality: null}}))).includes('D8'));
  assert.ok(ids(evaluate(ctxOf({estimate: notSteady, capturing: true, peak: {value: sig + 11, heading: null, quality: null}}))).includes('D8'));
  const fit = {valid: true, fitOk: true, theta3: 25};
  assert.ok(ids(evaluate(ctxOf({peak: {value: sig + 1, heading: 10, quality: null}, bearing: fit}))).includes('D8'));
  assert.ok(!ids(evaluate(ctxOf({peak: {value: sig + 1, heading: 10, quality: null}, bearing: {...fit, fitOk: false}}))).includes('D8'));
  assert.ok(!ids(evaluate(ctxOf({peak: {value: sig + 1, heading: 10, quality: null}, bearing: {...fit, theta3: 40}}))).includes('D8'));
  assert.ok(ids(evaluate(ctxOf({peak: {value: sig + 2, heading: null, quality: q + 6.5}}))).includes('D8'));
  assert.ok(!ids(evaluate(ctxOf({peak: {value: sig + 2, heading: null, quality: q + 5}}))).includes('D8'));
  assert.ok(!ids(evaluate(ctxOf({peak: null}))).includes('D8'));
});

test('D9 unsteady signal', () => {
  const est = estimateFor();
  est.readings = est.readings.map((r, i) => ({...r, raw: [-95, -100, -96, -101, -97][i]}));
  assert.ok(ids(evaluate(ctxOf({estimate: est}))).includes('D9'));
  est.signal.settled = false;
  assert.ok(!ids(evaluate(ctxOf({estimate: est}))).includes('D9'), 'needs steady');
  const r = evaluate(ctxOf({estimate: estimateFor(undefined, undefined, {signal: {R: 6.25, settled: false}, readings: []})})).find((f) => f.id === 'D9');
  assert.equal(r.detail, 'Spread 2.5 dB');
  assert.ok(!ids(evaluate(ctxOf())).includes('D9'));
  // Mark right after a sweep: only the capture's own readings count, not the turn before it.
  const swept = estimateFor(undefined, undefined, {signal: {settled: false, R: 0.3}});
  swept.readings = [-97, -93, -89, -86, -85, -85.1].map((raw, i) => ({...swept.readings[0], reading: i, t: i * 2500, raw}));
  const still = ctxOf({estimate: swept, capturing: true, capture: {t0: 10000, signals: [-85, -85.1], quality: []}});
  assert.equal(derive(still).sdSignal, null);
  assert.ok(!ids(evaluate(still)).includes('D9'));
  near(derive({...still, capture: {t0: 10000, signals: [-85, -85.1, -85], quality: []}}).sdSignal, 0.058, 0.001);
  assert.ok(ids(evaluate({...still, capture: {t0: 10000, signals: [-85, -89, -84], quality: []}})).includes('D9'));
  // Settled: only readings since the filter settled.
  const settled = {...swept, signal: {...swept.signal, settled: true, since: 3}};
  settled.readings = [-97, -93, -89, -85, -85.1, -85].map((raw, i) => ({...swept.readings[0], reading: i, t: i * 2500, raw}));
  assert.ok(derive(ctxOf({estimate: settled})).sdSignal < 0.1);
});

test('D10 needs 3 consecutive quality readings at 22 dBm or more', () => {
  const d = new Diagnostics();
  const at = (seq, tx) => ctxOf({snapshot: benchSnapshot({radio: {...benchSnapshot().radio, txPowerDbm: tx}}), estimate: estimateFor(undefined, undefined, {quality: {seq}})});
  const raw = (c) => ids(evaluate(c, d.mem));
  d.update(at(1, 23), {newEvidence: true});
  d.update(at(1, 23), {newEvidence: true}); // same quality reading: not counted twice
  d.update(at(2, 22), {newEvidence: true});
  assert.ok(!raw(at(2, 22)).includes('D10'));
  d.update(at(3, 22.5), {newEvidence: true});
  assert.ok(raw(at(3, 22.5)).includes('D10'));
  d.update(at(4, 21), {newEvidence: true});
  assert.ok(!raw(at(4, 21)).includes('D10'));
  assert.ok(!ids(evaluate(at(5, 30))).includes('D10'), 'stateless evaluate has no run history');
});

test('D11 own traffic', () => {
  const c = (rsrq, dl, peak) => ctxOf({estimate: estimateFor(undefined, undefined, {rsrq: {raw: rsrq, est: rsrq, sd: 0.1}}), snapshot: benchSnapshot({throughput: {dlBps: dl, ulBps: 0}}), dlPeakBps: peak});
  assert.ok(ids(evaluate(c(-11.5, 80e6, 100e6))).includes('D11'));
  assert.ok(!ids(evaluate(c(-11.5, 60e6, 100e6))).includes('D11'));
  assert.ok(!ids(evaluate(c(-10.5, 80e6, 100e6))).includes('D11'));
  assert.ok(!ids(evaluate(c(-11.5, 80e6, null))).includes('D11'));
});

test('D12 legacy timing', () => {
  assert.ok(ids(evaluate(ctxOf({snapshot: benchSnapshot({signal: {...benchSnapshot().signal, source: 'legacy'}})}))).includes('D12'));
  assert.ok(!ids(evaluate(ctxOf())).includes('D12'));
});

test('D13 conditions and suppression by warnings', () => {
  const g = evaluate(ctxOf({estimate: balanced()})).find((f) => f.id === 'D13');
  assert.equal(g.detail, 'RSRP -92.0 · quality 17.5 · margin 22.0');
  assert.ok(ids(evaluate(ctxOf({estimate: balanced(), snapshot: benchSnapshot({neighbours: []})}))).includes('D13'), 'no neighbour heard is fine');
  assert.ok(!ids(evaluate(ctxOf({estimate: estimateFor([-96, -97], [18, 18])}))).includes('D13'));
  assert.ok(!ids(evaluate(ctxOf({estimate: estimateFor([-90, -91], [12, 12])}))).includes('D13'));
  assert.ok(!ids(evaluate(ctxOf({estimate: balanced(), snapshot: benchSnapshot({neighbours: [coNeighbour(189, -96.5)]})}))).includes('D13'), 'margin under 6');
  assert.ok(!ids(evaluate(ctxOf({estimate: balanced(), snapshot: benchSnapshot({neighbours: [coNeighbour(190, -118)]})}))).includes('D13'), 'warn D5 active');
  assert.ok(!ids(evaluate(ctxOf({estimate: estimateFor([-92, -99])}))).includes('D13'), 'warn D6 active');
});

test('hysteresis: warn needs 2 counted hits to show and 3 counted misses to clear', () => {
  const d = new Diagnostics();
  const bad = ctxOf({estimate: balanced(), snapshot: benchSnapshot({neighbours: [coNeighbour(190, -118), coNeighbour(189, -114)]})});
  const good = ctxOf({estimate: balanced()});
  assert.deepEqual(ids(d.update(bad, {newEvidence: true})), []);
  assert.deepEqual(ids(d.update(bad, {newEvidence: false})), [], 'uncounted');
  assert.deepEqual(ids(d.update(bad, {newEvidence: true})), ['D5']);
  assert.deepEqual(ids(d.update(good, {newEvidence: true})), ['D5']);
  assert.deepEqual(ids(d.update(good, {newEvidence: false})), ['D5']);
  assert.deepEqual(ids(d.update(good, {newEvidence: true})), ['D5']);
  assert.deepEqual(ids(d.update(good, {newEvidence: false})), ['D5']);
  // D13 has held for 3 counted evaluations but stays hidden while D5 shows.
  assert.deepEqual(ids(d.update(good, {newEvidence: true})), ['D13']);
  d.reset();
  assert.deepEqual(ids(d.update(bad, {newEvidence: true})), []);
  d.update(good, {newEvidence: true});
  assert.deepEqual(ids(d.update(bad, {newEvidence: true})), [], 'a miss breaks the run');
});

test('sorting and display caps', () => {
  const f = (id, severity) => ({id, severity});
  const s = sortFindings([f('D13', 'good'), f('D9', 'warn'), f('D12', 'info'), f('D3', 'warn'), f('D2', 'block'), f('D1', 'block')]);
  assert.deepEqual(ids(s), ['D1', 'D2', 'D3', 'D9', 'D12', 'D13']);
  assert.deepEqual(ids(pick(s, 'portrait')), ['D1', 'D2', 'D3']);
  assert.deepEqual(ids(pick(s, 'desktop')), ['D1', 'D2', 'D3', 'D9', 'D12']);
  assert.equal(pick(s, 'record').length, 6);
});

test('grade thresholds', () => {
  assert.equal(grade('rsrp', -85), 'excellent');
  assert.equal(grade('signal', -95), 'good');
  assert.equal(grade('rsrp', -105), 'marginal');
  assert.equal(grade('rsrp', -105.1), 'fail');
  assert.equal(grade('quality', 13), 'good');
  assert.equal(grade('rsrq', -14.5), 'fail');
  assert.equal(grade('imbalance', -7), 'marginal');
  assert.equal(grade('margin', 10), 'excellent');
  assert.equal(grade('steadiness', 2.5), 'marginal');
  assert.equal(grade('grant', 'Authorized'), 'excellent');
  assert.equal(grade('grant', 'Granted'), 'fail');
  assert.equal(grade('quality', null), null);
  assert.equal(grade('bogus', 1), null);
  assert.equal(THRESHOLDS.margin.label, 'Clear of next cell');
});

const finalPos = (over = {}) => ({
  id: 'p1', index: 1, best: -82, rsrp: null, quality: {mean: 22, se: 0.3, lo: 21, hi: 23, n: 3, source: 'cinr'}, rsrq: -7, imbalance: 2, margin: 12,
  readings: [{t: 1, signal: -82, rx: [], quality: 22.1}, {t: 2, signal: -82, rx: [], quality: 21.6}, {t: 3, signal: -82, rx: [], quality: 22.3}],
  ...over,
});

test('acceptance verdicts', () => {
  const snap = benchSnapshot();
  assert.equal(acceptance({snapshot: snap, final: null}).verdict, 'incomplete');
  const ok = acceptance({snapshot: snap, final: finalPos()});
  assert.equal(ok.verdict, 'pass');
  assert.deepEqual(ok.rows.map((r) => r.metric), ['rsrp', 'quality', 'rsrq', 'imbalance', 'margin', 'steadiness', 'grant']);
  assert.ok(ok.rows.every((r) => r.grade === 'excellent'));
  assert.equal(acceptance({snapshot: snap, final: finalPos({best: -100})}).verdict, 'pass-notes');
  assert.equal(acceptance({snapshot: snap, final: finalPos({quality: {mean: 4, se: 1, n: 3}})}).verdict, 'fail');
  assert.equal(acceptance({snapshot: benchSnapshot({sas: {grant: 'Idle', registration: 'Registered'}}), final: finalPos()}).verdict, 'fail');
  const noMargin = acceptance({snapshot: snap, final: finalPos({margin: null})});
  const m = noMargin.rows.find((r) => r.metric === 'margin');
  assert.equal(m.grade, 'good');
  assert.equal(m.note, 'No other cell heard');
  assert.equal(noMargin.verdict, 'pass');
  const shaky = acceptance({snapshot: snap, final: finalPos({readings: [10, 18, 13].map((q, t) => ({t, signal: -82, rx: [], quality: q}))})});
  assert.equal(shaky.rows.find((r) => r.metric === 'steadiness').grade, 'fail');
  // Position readings hold one entry per quality reading: equal values are a steady link, not one reading.
  const flat = acceptance({snapshot: snap, final: finalPos({readings: [{t: 1, quality: 22}, {t: 2, quality: 22}, {t: 3, quality: 22}]})});
  assert.equal(flat.rows.find((r) => r.metric === 'steadiness').grade, 'excellent');
  const thin = acceptance({snapshot: snap, final: finalPos({readings: [{t: 1, quality: 22}, {t: 2, quality: null}, {t: 3, quality: null}]})});
  assert.equal(thin.rows.find((r) => r.metric === 'steadiness').value, null, 'one quality reading is not 3');
});
