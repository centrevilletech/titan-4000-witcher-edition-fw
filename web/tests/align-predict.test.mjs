import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CQI64, CQI256, MCS_ITBS_64, MCS_ITBS_256, MCS_ITBS_UL, TBS, TDD, PRB_DL, PRB_UL, DWPTS_PRB, DEFAULTS,
  cqiFromSinr, dlMbps, ulMbps, modulationOf, predict, potentialSmooth,
} from '../src/align/predict.js';

const near = (a, b, tol = 0.01, msg) => assert.ok(Math.abs(a - b) <= tol, `${msg ?? ''} ${a} vs ${b}`);
const cfg2 = {sa: 2, ssp: 7};
const pcc = (sinr, extra = {}) => ({role: 'pcc', bwMhz: 20, sinr, sinrSd: 0, ...extra});
const scc = (sinr, extra = {}) => ({role: 'scc', bwMhz: 20, sinr, sinrSd: 0, ...extra});
const base = (carriers, extra = {}) => ({carriers, input: 'cinr', caps: {dl256: false, maxLayers: 2, catBitsPerTti: 452256}, tdd: cfg2, ...extra});

test('table integrity', () => {
  for (const [k, col] of Object.entries(TBS)) assert.equal(col.length, 34, `TBS ${k}`);
  assert.deepEqual(Object.keys(TBS).map(Number).sort((a, b) => a - b), [18, 25, 37, 50, 56, 75, 100]);
  assert.equal(MCS_ITBS_64.length, 29);
  assert.equal(MCS_ITBS_256.length, 28);
  assert.equal(MCS_ITBS_UL.length, 29);
  for (const t of [CQI64, CQI256]) for (const key of ['mod', 'rate', 'eff', 'thr', 'mcs']) assert.equal(t[key].length, 15, key);
  for (const t of [CQI64, CQI256]) for (let i = 1; i < 15; i++) {
    assert.ok(t.thr[i] > t.thr[i - 1] && t.eff[i] > t.eff[i - 1] && t.mcs[i] >= t.mcs[i - 1]);
  }
  for (const n of Object.values(PRB_DL)) assert.equal(DWPTS_PRB[n], Math.floor(0.75 * n));
  assert.deepEqual(PRB_UL, {5: 24, 10: 48, 15: 72, 20: 96});
  for (const [D, S, U] of Object.values(TDD)) assert.equal(D + S + U, 10);
  // Rel-12 256QAM row 27 is deliberately smaller than row 26.
  assert.ok(TBS[100][27] < TBS[100][26]);
  assert.equal(TBS[100][26], 75376);
  assert.equal(TBS[100][33], 97896);
});

test('table lookups: MCS to I_TBS and modulation', () => {
  assert.equal(MCS_ITBS_64[17], 15);
  assert.equal(MCS_ITBS_64[28], 26);
  assert.equal(MCS_ITBS_256[27], 33);
  assert.equal(MCS_ITBS_256[20], 25);
  assert.equal(MCS_ITBS_UL[24], 22);
  assert.equal(MCS_ITBS_UL[26], 24);
  assert.equal(modulationOf(9, '64'), 'QPSK');
  assert.equal(modulationOf(10, '64'), '16QAM');
  assert.equal(modulationOf(17, '64'), '64QAM');
  assert.equal(modulationOf(4, '256'), 'QPSK');
  assert.equal(modulationOf(10, '256'), '16QAM');
  assert.equal(modulationOf(19, '256'), '64QAM');
  assert.equal(modulationOf(20, '256'), '256QAM');
  assert.equal(modulationOf(10, 'ul'), 'QPSK');
  assert.equal(modulationOf(20, 'ul'), '16QAM');
  assert.equal(modulationOf(21, 'ul'), '64QAM');
  assert.equal(modulationOf(null, '64'), null);
});

test('cqiFromSinr picks the highest threshold met', () => {
  assert.equal(cqiFromSinr(17.28 - 4.4, CQI64), 10);
  assert.equal(cqiFromSinr(-6.8, CQI64), 0);
  assert.equal(cqiFromSinr(-6.7, CQI64), 1);
  assert.equal(cqiFromSinr(22.7, CQI64), 15);
  assert.equal(cqiFromSinr(99, CQI256), 15);
  assert.equal(cqiFromSinr(24.6, CQI256), 13);
  assert.equal(cqiFromSinr(NaN, CQI64), 0);
});

test('dlMbps worked numbers and TDD fraction', () => {
  near(dlMbps(28, 2, 20, cfg2, false), 112.47);
  near(dlMbps(27, 2, 20, cfg2, true), 147.63);
  near(dlMbps(17, 2, 20, cfg2, false), 45.86);
  near(dlMbps(28, 2, 20, {sa: 1, ssp: 7}, false), 82.3, 0.1);
  near(dlMbps(28, 1, 20, cfg2, false), 112.47 / 2);
  // SSF 0/5 carry no PDSCH, SSF 9 uses 0.375 of the full column.
  near(dlMbps(28, 1, 20, {sa: 2, ssp: 0}, false), 6 * 75376 * 100 / 1e6);
  near(dlMbps(28, 1, 20, {sa: 2, ssp: 5}, false), 6 * 75376 * 100 / 1e6);
  near(dlMbps(28, 1, 20, {sa: 2, ssp: 9}, false), (6 * 75376 + 2 * Math.round(0.375 * 75376)) * 100 / 1e6);
  near(dlMbps(28, 1, 20, {sa: 5, ssp: 7}, false), (8 * 75376 + 55056) * 100 / 1e6);
  near(dlMbps(28, 1, 10, cfg2, false), (6 * 36696 + 2 * 27376) * 100 / 1e6);
  assert.equal(dlMbps(28, 2, 3, cfg2, false), 0);
  assert.equal(dlMbps(29, 2, 20, cfg2, false), 0);
});

test('ulMbps approximation', () => {
  // MCS 26 is I_TBS 24: 2 x round(61664*96/100) = 11.84 vs 11.85 from the real 96-PRB column.
  near(ulMbps(26, 20, cfg2), 11.84);
  assert.ok(Math.abs(ulMbps(26, 20, cfg2) - 11.85) / 11.85 < 0.02);
  near(ulMbps(24, 20, cfg2), 2 * Math.round(55056 * 0.96) * 100 / 1e6);
  near(ulMbps(26, 20, {sa: 1, ssp: 7}), 2 * ulMbps(26, 20, cfg2));
  assert.equal(ulMbps(26, 3, cfg2), 0);
});

test('predict: bench PCC from CINR, rank 2', () => {
  const p = predict(base([pcc(17.28)]));
  assert.equal(p.carriers.length, 1);
  assert.deepEqual({...p.carriers[0], dlMbps: undefined}, {role: 'pcc', cqi: 10, mcs: 17, rank: 2, modulation: '64QAM', dlMbps: undefined});
  near(p.dlMbps, 38.98);
  near(p.carriers[0].dlMbps, 38.98);
  assert.equal(p.dlModulation, '64QAM');
  assert.equal(p.basis, 'model');
  assert.equal(p.dlLo, p.dlMbps);
  assert.equal(p.dlHi, p.dlMbps);
  assert.ok(p.assumptions.includes('64QAM table assumed'));
  assert.ok(!p.assumptions.some(a => a.startsWith('TDD')));
  assert.ok(predict({...base([pcc(17.28)]), tdd: undefined}).assumptions.includes('TDD 2/7 assumed'));
});

test('predict: rank choice and input scale offsets', () => {
  // Low SINR: rank 1 (offset -1.5) beats rank 2 (offset -4.4).
  const low = predict(base([pcc(2)]));
  assert.equal(low.carriers[0].rank, 1);
  assert.equal(low.carriers[0].cqi, cqiFromSinr(0.5, CQI64));
  const one = predict({...base([pcc(17.28)]), caps: {dl256: false, maxLayers: 1, catBitsPerTti: 452256}});
  assert.equal(one.carriers[0].rank, 1);
  // At 16.2 dB the CINR scale (rank 2 at -4.4) gives CQI 10, the SINR scale (-5.0) gives CQI 9; rank 2 still wins.
  const c = predict(base([pcc(16.2)])), s = predict({...base([pcc(16.2)]), input: 'sinr'});
  assert.deepEqual([c.carriers[0].cqi, c.carriers[0].rank], [10, 2]);
  assert.deepEqual([s.carriers[0].cqi, s.carriers[0].rank, s.carriers[0].mcs], [9, 2, 15]);
  near(s.dlMbps, dlMbps(15, 2, 20, cfg2, false) * 0.85);
});

test('predict: reported CQI only when fresh on the PCC with matching RI', () => {
  const fresh = predict(base([pcc(17.28, {cqi: 12, ri: 2, cqiFresh: true})]));
  assert.equal(fresh.basis, 'reported-cqi');
  assert.equal(fresh.carriers[0].cqi, 12);
  assert.equal(fresh.carriers[0].mcs, 21);
  const stale = predict(base([pcc(17.28, {cqi: 12, ri: 2, cqiFresh: false})]));
  assert.equal(stale.basis, 'model');
  assert.equal(stale.carriers[0].cqi, 10);
  const onScc = predict(base([pcc(17.28), scc(17.28, {cqi: 12, ri: 2, cqiFresh: true})]));
  assert.equal(onScc.basis, 'model');
  assert.equal(onScc.carriers[1].cqi, 10);
  // Fresh RI 1 is honoured even though rank 2 would model higher; its CQI is the reported one.
  const ri1 = predict(base([pcc(17.28, {cqi: 9, ri: 1, cqiFresh: true})]));
  assert.equal(ri1.carriers[0].rank, 1);
  assert.equal(ri1.carriers[0].cqi, 9);
  assert.equal(ri1.basis, 'reported-cqi');
  const noRi = predict(base([pcc(17.28, {cqi: 12, ri: null, cqiFresh: true})]));
  assert.equal(noRi.basis, 'model');
  assert.equal(noRi.carriers[0].rank, 2);
});

test('predict: CA scaling and category cap', () => {
  const one = predict(base([pcc(17.28)])), three = predict(base([pcc(17.28), scc(17.28), scc(17.28)]));
  near(three.dlMbps, 3 * one.dlMbps);
  const tenMhz = predict(base([pcc(17.28), scc(17.28, {bwMhz: 10})]));
  near(tenMhz.carriers[1].dlMbps, dlMbps(17, 2, 10, cfg2, false) * 0.85);
  near(tenMhz.dlMbps, one.dlMbps + tenMhz.carriers[1].dlMbps);
  const hi = [pcc(40), scc(40), scc(40)];
  const capped = predict({...base(hi), caps: {dl256: true, maxLayers: 2, catBitsPerTti: 452256}});
  near(capped.carriers.reduce((s, c) => s + c.dlMbps, 0), 3 * 147.63 * 0.85, 0.05);
  near(capped.dlMbps, 452256 * 7.5 * 100 / 1e6 * 0.85, 0.05);
  near(capped.dlMbps, 288.3, 0.05);
  assert.equal(capped.dlModulation, '256QAM');
  assert.ok(!capped.assumptions.includes('64QAM table assumed'));
  const uncapped = predict(base(hi));
  near(uncapped.dlMbps, 3 * 112.47 * 0.85, 0.05);
  near(uncapped.dlMbps, 286.8, 0.05);
  assert.ok(uncapped.dlMbps < capped.dlMbps);
  // Default category cap applies when caps omit it; a smaller category binds.
  near(predict({...base(hi), caps: {dl256: false}}).dlMbps, uncapped.dlMbps);
  near(predict({...base(hi), caps: {dl256: false, catBitsPerTti: 301504}}).dlMbps, 301504 * 7.5 * 100 / 1e6 * 0.85);
});

test('predict: interval, monotonicity and potential', () => {
  const p = predict(base([pcc(15, {sinrSd: 1.2}), scc(9, {sinrSd: 1})]));
  assert.ok(p.dlLo <= p.dlMbps && p.dlMbps <= p.dlHi);
  assert.ok(p.dlLo < p.dlHi);
  const lo = predict(base([pcc(15 - 1.645 * 1.2), scc(9 - 1.645)]));
  near(p.dlLo, lo.dlMbps, 1e-9);
  let prev = -1, prevPot = -1;
  for (let s = -15; s <= 40; s += 0.25) {
    const q = predict(base([pcc(s), scc(s - 3)]));
    assert.ok(q.dlMbps >= prev - 1e-9, `monotone at ${s}`);
    assert.ok(q.potential >= prevPot, `potential monotone at ${s}`);
    assert.ok(Number.isInteger(q.potential) && q.potential >= 0 && q.potential <= 100);
    prev = q.dlMbps; prevPot = q.potential;
  }
  const ideal = CQI64.thr[14] - DEFAULTS.rankOffset.cinr[2] + 1;
  assert.equal(predict(base([pcc(ideal), scc(ideal)])).potential, 100);
  assert.equal(predict({...base([pcc(28.2 + 4.4 + 1)]), caps: {dl256: true}}).potential, 100);
  const dead = predict(base([pcc(-20)]));
  assert.equal(dead.potential, 0);
  assert.equal(dead.dlMbps, 0);
  assert.equal(dead.carriers[0].mcs, null);
  assert.equal(dead.carriers[0].modulation, null);
  assert.equal(dead.dlModulation, null);
  assert.equal(predict(base([pcc(17.28)])).potential, Math.round(100 * 38.98 / (112.47 * 0.85)));
  const empty = predict(base([]));
  assert.equal(empty.dlMbps, 0);
  assert.equal(empty.potential, 0);
  assert.equal(empty.ulMbps, null);
});

test('predict: uplink', () => {
  // 17.28 - 8 = 9.28 -> CQI 8 -> MCS 13 (16QAM).
  const p = predict(base([pcc(17.28)]));
  near(p.ulMbps, ulMbps(13, 20, cfg2) * 0.85);
  assert.equal(p.ulModulation, '16QAM');
  const obs = predict({...base([pcc(17.28)]), ulMcsObserved: 26});
  near(obs.ulMbps, ulMbps(26, 20, cfg2) * 0.85);
  assert.equal(obs.ulModulation, '64QAM');
  const hot = predict({...base([pcc(17.28)]), txPowerDbm: 23});
  near(hot.ulMbps, ulMbps(9, 20, cfg2) * 0.85);
  assert.equal(hot.ulModulation, 'QPSK');
  near(predict({...base([pcc(17.28)]), txPowerDbm: 20.9}).ulMbps, p.ulMbps);
  const none = predict(base([pcc(-2)]));
  assert.equal(none.ulMbps, 0);
  assert.equal(none.ulModulation, null);
});

test('calibration: DEFAULTS by default, cal overrides offsets and eta', () => {
  const p = predict(base([pcc(17.28)]));
  const same = predict({...base([pcc(17.28)]), cal: {eta: DEFAULTS.eta, rankOffset: {cinr: {...DEFAULTS.rankOffset.cinr}}}});
  assert.deepEqual(same, p);
  const eta = predict({...base([pcc(17.28)]), cal: {eta: 0.9}});
  near(eta.dlMbps, p.dlMbps / 0.85 * 0.9, 1e-9);
  // A gentler rank-2 offset lifts CQI 10 -> 11 at 17.28 dB.
  const off = predict({...base([pcc(17.28)]), cal: {rankOffset: {cinr: {2: -3.0}}}});
  assert.equal(off.carriers[0].cqi, 11);
  assert.equal(off.carriers[0].rank, 2);
  // Only the named input scale is affected.
  assert.deepEqual(predict({...base([pcc(17.28)]), cal: {rankOffset: {sinr: {2: -3.0}}}}), p);
  const ul = predict({...base([pcc(17.28)]), cal: {ulGapDb: 4}});
  near(ul.ulMbps, ulMbps(CQI64.mcs[cqiFromSinr(13.28, CQI64) - 1], 20, cfg2) * 0.85);
  assert.equal(DEFAULTS.eta, 0.85);
  assert.equal(DEFAULTS.catBitsPerTti, 452256);
});

test('potentialSmooth tracks SINR smoothly in 0..1', () => {
  const at = s => potentialSmooth(base([pcc(s), scc(s)]));
  assert.equal(at(-30), 0);
  assert.equal(at(CQI64.thr[14] - DEFAULTS.rankOffset.cinr[2] + 1), 1);
  let prev = -1;
  for (let s = -12; s <= 35; s += 0.5) {
    const v = at(s);
    assert.ok(v >= prev && v >= 0 && v <= 1, `smooth at ${s}`);
    prev = v;
  }
  assert.ok(at(17.28) > 0.5 && at(17.28) < 1);
  assert.ok(potentialSmooth({...base([pcc(17.28)]), caps: {dl256: true}}) < at(17.28));
  assert.equal(potentialSmooth(base([])), 0);
});

test('module imports without browser globals', () => {
  assert.equal(typeof globalThis.window, 'undefined');
  assert.equal(typeof predict, 'function');
});
