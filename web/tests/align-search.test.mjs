import {test} from 'node:test';
import assert from 'node:assert/strict';
import {phi, wrap180, circularMean, summarize, pooledSigma, compare, Capture, PeakTracker, Bracket, fitBearing,
  bearingPoints, AlignSession, roundTurn, guidance, COMPARE, CAPTURE} from '../src/align/search.js';

const near = (a, b, tol, msg) => assert.ok(Math.abs(a - b) <= tol, `${msg || ''} expected ${b} ±${tol}, got ${a}`);
const pos = (o) => ({pci:190, t:0, flags:{lowConfidence:false}, readings:[], ...o});
const est = ({raw = -84, reading = 1, t = 0, deadband = 0.5, q = 18, qt = t, R = 0.04, readings = [], freshness = 'live', trend = null, ageMs = 0} = {}) => ({
  t, freshness, readings,
  signal:{raw, chains:[raw, raw - 1], reading, t, readingT:t, deadband, R, ageMs, trend},
  quality:{raw:q, t:qt, R:0.1, source:'cinr', sinr:18},
  rsrq:{raw:-9},
  cadence:{signalMs:2500, qualityMs:8300, signalEta:{p50:3000, p90:5000, overdue:false}}
});
const snap = ({pci = 190, eci = 2616332, seq = 1, reading = 1, t = 0, heartbeat = false, qseq = 0, qt = 0, connected = true} = {}) => ({
  connected, attached:true, paused:false, stale:false, cell:{pci, eci, earfcn:56040},
  signal:{seq, reading, t, readingT:t, heartbeat, rsrp:[-84, -85]}, quality:qseq ? {seq:qseq, t:qt} : null
});

test('phi and wrap180', () => {
  assert.equal(phi(0), 0.5);
  near(phi(1.96), 0.975, 1e-4);
  near(phi(-1.96), 0.025, 1e-4);
  assert.equal(wrap180(190), -170);
  assert.equal(wrap180(-190), 170);
  near(circularMean([359, 1]), 0, 1e-9, 'mean across north') ;
  assert.equal(circularMean([]), null);
});

test('summarize uses the pooled sigma, R and floor', () => {
  const s = summarize([-84, -84.2, -83.8], {pooledSigma:0.5, df:4, floor:0.1});
  near(s.mean, -84, 1e-9); near(s.se, 0.5 / Math.sqrt(3), 1e-9); near(s.hi - s.mean, 2.78 * s.se, 1e-9);
  assert.equal(summarize([1, 1], {floor:0.29}).se, 0.29 / Math.SQRT2);
  near(summarize([1], {pooledSigma:0.1, R:1}).se, 1, 1e-9);
  assert.equal(summarize([]).n, 0);
});

test('pooledSigma: prior alone, then pooled residuals', () => {
  assert.deepEqual(pooledSigma([], 'signal'), {s:0.5, df:4});
  assert.deepEqual(pooledSigma([], 'quality'), {s:1, df:4});
  const p = pooledSigma([pos({readings:[{signal:-84}, {signal:-82}]}), pos({readings:[{signal:-80}, {signal:-80}, {signal:-80}]})], 'signal');
  assert.equal(p.df, 7); near(p.s, Math.sqrt((4 * 0.25 + 2) / 7), 1e-12);
  assert.equal(pooledSigma([pos({readings:[{signal:-90, quality:null}]})], 'quality').s, 1);
});

test('compare: probabilities follow the normal model', () => {
  const a = pos({signal:{mean:-81, se:0.3}}), b = pos({signal:{mean:-84, se:0.3}});
  const c = compare(a, b, 'signal'), se = Math.sqrt(0.18);
  assert.equal(c.verdict, 'better'); near(c.delta, 3, 1e-12); near(c.seDelta, se, 1e-12);
  near(c.pBetter, phi(2.5 / se), 1e-9); near(c.pWorse, phi(-3.5 / se), 1e-9);
  near(c.pSame, phi(-2 / se) - phi(-4 / se), 1e-9);
  assert.equal(compare(b, a, 'signal').verdict, 'worse');
  const s = compare(pos({signal:{mean:-83.8, se:0.2}}), pos({signal:{mean:-84, se:0.2}}), 'signal');
  assert.equal(s.verdict, 'same'); near(s.pSame, phi(0.8 / Math.sqrt(0.08)) - phi(-1.2 / Math.sqrt(0.08)), 1e-9);
  assert.equal(compare(pos({signal:{mean:-84, se:1}}), pos({signal:{mean:-84.6, se:1}}), 'signal').verdict, 'unsure');
  assert.equal(compare(a, {...b, pci:211}, 'signal').verdict, 'different-cell');
  assert.equal(compare(a, b, 'quality').verdict, 'unsure');
  const far = compare(a, {...b, t:600000}, 'signal');
  near(far.seDelta, Math.sqrt(0.18 + COMPARE.signal.drift * 600), 1e-12);
  assert.ok(far.seDelta > c.seDelta);
});

test('Capture: settle window, fresh readings and quality', () => {
  const c = new Capture({t0:1000, pci:190, eci:2616332});
  assert.equal(c.label(), 'Hold still · reading 0 of 3');
  assert.equal(c.offer(est({t:1500}), snap({reading:5, t:1500}), null, 1600).n, 0, 'reading before t0+750 ignored');
  assert.equal(c.offer(est({t:1800}), snap({reading:6, t:1800}), null, 1800).n, 1);
  assert.equal(c.offer(est({t:1900}), snap({reading:6, t:1900}), null, 1900).n, 1, 'same reading poll');
  assert.equal(c.offer(est({t:2000, raw:-84.3}), snap({seq:3, reading:6, t:2000}), null, 2000).n, 1, 'revision does not count');
  assert.equal(c.got[0].signal, -84.3);
  assert.equal(c.offer(est({t:4000}), snap({seq:4, reading:7, t:4000, heartbeat:true}), null, 4000).n, 1, 'heartbeat never counts');
  c.offer(est({t:4500}), snap({seq:5, reading:8, t:4500}), null, 4500);
  const st = c.offer(est({t:7000}), snap({seq:6, reading:9, t:7000}), null, 7000);
  assert.equal(st.status, 'collecting'); assert.equal(st.n, 3);
  assert.equal(c.label(), 'Hold still · waiting for quality');
  const done = c.offer(est({t:9000, q:18.5, qt:9000}), snap({seq:6, reading:9, t:7000, qseq:4, qt:9000}), null, 9000);
  assert.equal(done.status, 'done'); assert.equal(done.nQuality, 1);
  const s = new AlignSession(), r = s.add(c.result(s));
  assert.equal(r.index, 1); assert.equal(r.n, 3); assert.equal(r.quality.mean, 18.5); assert.equal(r.quality.source, 'cinr');
  assert.equal(r.flags.qualityHeld, false); assert.equal(r.imbalance, 1); assert.equal(r.best, r.rx[0]);
  near(r.signal.mean, (-84.3 - 84 - 84) / 3, 1e-9); assert.equal(r.signal.se, 0.5 / Math.sqrt(3));
  assert.equal(r.readings.length, 3); assert.equal(r.readings[0].quality, 18.5);
});

test('Capture: quality idle, restart, timeout and abort', () => {
  let c = new Capture({t0:0, pci:190, eci:2616332});
  for (let i = 1; i <= 3; i++) c.offer(est({t:1000 * i, qt:null}), snap({seq:i, reading:i, t:1000 * i}), null, 1000 * i);
  assert.equal(c.offer(est({t:3000, qt:-30000}), snap({seq:3, reading:3, t:3000}), null, 3000).status, 'done');
  assert.equal(c.final.flags.qualityHeld, true); assert.equal(c.final.reason, 'qualityHeld');
  const s = new AlignSession(), r = c.result(s);
  assert.equal(r.quality.n, 1); assert.equal(r.quality.se, 1); assert.equal(r.flags.qualityHeld, true);

  c = new Capture({t0:0, pci:190, eci:2616332});
  c.offer(est({t:1000}), snap({seq:1, reading:1, t:1000}), null, 1000);
  const re = c.offer(est({t:2000, raw:-79}), snap({seq:2, reading:2, t:2000}), null, 2000);
  assert.equal(re.status, 'restarted'); assert.equal(re.n, 1);
  c.offer(est({t:3000, raw:-84}), snap({seq:3, reading:3, t:3000}), null, 3000);
  assert.equal(c.flags.unsteady, true, 'second jump flags unsteady');
  assert.equal(c.got.length, 2);

  c = new Capture({t0:0, pci:190});
  c.offer(est({t:1000}), snap({seq:1, reading:1, t:1000}), null, 1000);
  c.offer(est({t:2000}), snap({seq:2, reading:2, t:2000}), null, 2000);
  const lc = c.offer(est({t:25000}), snap({seq:2, reading:2, t:2000}), null, 25000);
  assert.equal(lc.status, 'done'); assert.equal(lc.flags.lowConfidence, true);

  c = new Capture({t0:0, pci:190});
  c.offer(est({t:1000}), snap({seq:1, reading:1, t:1000}), null, 1000);
  assert.equal(c.offer(est({t:25000}), snap({seq:1, reading:1, t:1000}), null, 25000).status, 'failed');

  c = new Capture({t0:0, pci:190, eci:2616332});
  const ab = c.offer(est({t:1000}), snap({pci:211, t:1000}), null, 1000);
  assert.equal(ab.status, 'aborted'); assert.equal(ab.reason, 'cell');
  assert.equal(c.offer(est({t:2000}), snap({t:2000}), null, 2000).status, 'aborted', 'final status sticks');

  c = new Capture({t0:0, pci:190});
  const pose = h => ({heading:h, valid:true, sd:1, source:'sim', relative:false});
  c.offer(est({t:1000}), snap({seq:1, reading:1, t:1000}), pose(100), 1000);
  const mv = c.offer(est({t:2000}), snap({seq:2, reading:2, t:2000}), pose(105), 2000);
  assert.equal(mv.status, 'restarted'); assert.equal(mv.reason, 'moved'); assert.equal(mv.n, 0);
  assert.equal(CAPTURE.need, 3);
});

test('PeakTracker: confirmation, spikes, passed', () => {
  const p = new PeakTracker(), feed = (raw, reading) => p.offer(est({raw, reading, t:reading * 2500, deadband:0.5}), {heading:200 + reading, valid:true});
  feed(-90, 1); assert.equal(feed(-89.8, 2).newPeak, true); near(p.peak.value, -89.9, 1e-9);
  assert.equal(feed(-80, 3).newPeak, false, 'single spike');
  assert.equal(feed(-89, 4).newPeak, false);
  feed(-85, 5); assert.equal(feed(-84.8, 6).newPeak, true); near(p.peak.value, -84.9, 1e-9); assert.equal(p.peak.heading, 206);
  assert.equal(p.atPeak(est({raw:-85.2})), true);
  feed(-88, 7); assert.equal(p.passed(est({deadband:0.5})), false, 'one low reading');
  feed(-88.5, 8); assert.equal(p.passed(est({deadband:0.5})), true); assert.equal(p.passedOnce, true);
  feed(-84.9, 9); assert.equal(p.passed(est({deadband:0.5})), false);
  assert.equal(p.recent(9 * 2500), -80);
  assert.equal(p.recent(9 * 2500 + 40000), null);
  p.reset(); assert.equal(p.peak, null);
});

test('Bracket walks left edge, right edge, done', () => {
  const b = new Bracket(), peak = {value:-80};
  assert.equal(b.start(est(), null), false); assert.equal(b.state, 'idle');
  assert.equal(b.start(est({reading:0}), peak), true); assert.equal(b.state, 'left');
  const o = (raw, reading, p = peak) => b.offer(est({raw, reading, t:reading * 2000}), p);
  o(-82, 1); o(-83.5, 2); assert.equal(o(-83.2, 3), 'left-edge');
  assert.equal(o(-82, 4), 'right');
  o(-84, 5); o(-84, 6); assert.equal(b.state, 'right', 'needs a reading near the peak first');
  o(-80.5, 7); o(-83.1, 8); assert.equal(o(-83.4, 9), 'right-edge');
  assert.equal(o(-85, 14), 'done', '8 s later');
  b.cancel(); assert.equal(b.state, 'idle');
});

const shape = h => -80 - 12 * (wrap180(h - 212) / 60) ** 2;
const pts = (hs, f = shape) => hs.map(h => ({heading:(h + 360) % 360, y:f(h), se:0.1, sigmaH:2, relative:false}));

test('fitBearing recovers a synthetic peak', () => {
  const fit = fitBearing(pts([180, 195, 210, 225, 240]));
  assert.equal(fit.valid, true); assert.equal(fit.fitOk, true);
  near(wrap180(fit.theta0 - 212), 0, 1); near(wrap180(fit.recommended - 212), 0, 1.5);
  assert.ok(fit.theta3 > 45 && fit.theta3 < 80, `theta3 ${fit.theta3}`);
  assert.ok(fit.gainAt(212) < 0.1); assert.ok(fit.pWithinAt(212) > 0.9); assert.ok(fit.pWithinAt(150) < 0.1);
  assert.equal(fit.edge, null);
  const noisy = fitBearing(pts([180, 195, 210, 225, 240], h => shape(h) + Math.sin(h) * 0.3).map(p => ({...p, se:0.4, sigmaH:6})));
  near(wrap180(noisy.theta0 - 212), 0, 3);
});

test('fitBearing validity, wrap and fixed beamwidth', () => {
  assert.equal(fitBearing(pts([200, 210])).reason, 'few');
  assert.equal(fitBearing(pts([200, 200.2, 210, 210])).reason, 'few');
  assert.equal(fitBearing(pts([200, 205, 215])).reason, 'span');
  const north = fitBearing(pts([350, 365, 380], h => -80 - 12 * (wrap180(h - 5) / 60) ** 2));
  assert.equal(north.valid, true); near(wrap180(north.theta0 - 5), 0, 1.5);
  const fixed = fitBearing(pts([180, 195, 210, 225, 240]), {theta3Grid:[60]});
  assert.equal(fixed.theta3, 60); near(fixed.expectedLossAt(222), 0.33, 0.03); near(fixed.expectedLossAt(212), 0, 0.03);
  const two = fitBearing([{heading:190, y:-81.5}, {heading:200, y:-81.5 + 0}, {heading:210, y:-80}].map(p => ({...p, se:0.05, sigmaH:0.1})), {theta3Grid:[60], tau:0.01});
  assert.ok(two.valid);
  const edge = fitBearing(pts([150, 165, 180], h => -80 - 12 * (wrap180(h - 212) / 60) ** 2));
  assert.equal(edge.edge, 'right');
  // Only two points survive the 10 dB trim: under-determined, so no fit.
  assert.equal(fitBearing(pts([100, 115, 130], h => -80 - 12 * (wrap180(h - 212) / 60) ** 2)).reason, 'few');
  assert.equal(fitBearing([{heading:200, y:-80}, {heading:215, y:-81}, {heading:260, y:-95}].map(p => ({...p, se:0.3, sigmaH:6}))).valid, false);
  // Near-full-circle sweep whose boresight sits opposite the mean heading (unwrap around the peak).
  const L = (h, b) => Math.min(12 * (wrap180(h - b) / 54) ** 2, 20), ring = [];
  for (let h = 0; h <= 330; h += 15) ring.push(h);
  for (let h = 0; h <= 90; h += 10) ring.push(h);
  for (const b of [175, 200, 231, 245]) {
    const f = fitBearing(ring.map(h => ({heading:h, y:-80 - L(h, b), se:0.3, sigmaH:2})));
    assert.ok(f.fitOk, `fit ok at ${b}`); near(wrap180(f.theta0 - b), 0, 1.5);
  }
  const rel = fitBearing(pts([180, 195, 210]).map(p => ({...p, relative:true})).concat(pts([0])));
  assert.equal(rel.relative, true); assert.equal(rel.n, 3);
});

test('bearingPoints collects headed positions and sweep readings', () => {
  const s = new AlignSession();
  s.add(pos({id:'a', signal:{mean:-84, se:0.3}, heading:{deg:200, sd:1, source:'abs', relative:false}}));
  s.add(pos({id:'b', signal:{mean:-84, se:0.3}, heading:null}));
  s.logSweep(est({raw:-85, reading:1}), {heading:210, valid:true, sd:1, source:'sim', relative:false}, 190);
  s.logSweep(est({raw:-85, reading:2}), {heading:220, valid:true, sd:1, source:'sim', relative:false}, 211);
  const p = bearingPoints(s, {pci:190, R:0.01});
  assert.equal(p.length, 2); assert.equal(p[0].sigmaH, 6); assert.equal(p[1].sigmaH, 2); assert.equal(p[1].se, 0.3);
});

test('AlignSession: best, verdicts, lock, cell change, undo', () => {
  const s = new AlignSession();
  const p1 = s.add(pos({id:'p1', index:1, signal:{mean:-84, se:0.2}, quality:{mean:15, se:0.3}}));
  const p2 = s.add(pos({id:'p2', index:2, signal:{mean:-84.3, se:0.2}, quality:{mean:19, se:0.3}}));
  assert.deepEqual(s.best(), {position:p2, basis:'quality'});
  assert.equal(s.verdicts().get('p1').verdict, 'worse');
  p2.quality.mean = 15.4; assert.deepEqual(s.best(), {position:p1, basis:'signal'}, 'not significant');
  p2.quality.mean = 19; p2.signal.mean = -85.5; assert.equal(s.best().position, p1, 'significantly weaker signal');
  p2.signal = {mean:-87.5, se:3}; assert.equal(s.best().position, p1, 'outside 3 dB');
  s.add(pos({id:'p3', index:3, signal:{mean:-70, se:0.2}, flags:{lowConfidence:true}}));
  assert.equal(s.best().position, p1, 'low confidence skipped');
  assert.equal(s.undo().id, 'p3');
  s.startLock(est({readings:[{raw:-84.2}, {raw:-84}], deadband:0.5}));
  near(s.lock.baseline, -84.1, 1e-9); assert.equal(s.lock.band, 1.5);
  assert.equal(s.offerLock(est({raw:-86, reading:10})), 'dropped'); near(s.lock.drop, 1.9, 1e-9);
  assert.equal(s.offerLock(est({raw:-86, reading:10})), 'dropped', 'same reading ignored');
  ['watching', 'watching', 'locked'].forEach((want, i) => assert.equal(s.offerLock(est({raw:-84, reading:11 + i})), want));
  s.onCellChange(190, 211);
  assert.equal(s.positions.length, 0); assert.equal(s.archived[0].pci, 190); assert.equal(s.archived[0].positions.length, 2); assert.equal(s.lock, null);
  assert.equal(s.best(), null);
  for (let i = 0; i < 205; i++) s.logSweep(est({reading:i}), null, 211);
  assert.equal(s.sweep.length, 200);
  assert.ok(JSON.parse(JSON.stringify(s)).archived.length === 1);
});

test('roundTurn', () => {
  assert.equal(roundTurn(3).text, 'a little');
  assert.equal(roundTurn(12).text, 'about 10°'); assert.equal(roundTurn(-12).value, 10);
  assert.equal(roundTurn(4).text, 'about 5°');
  assert.deepEqual(roundTurn(80), {value:45, text:'about 45°', clamped:true});
});

test('guidance catalogue', () => {
  const base = {step:'find', estimate:est({t:10000}), snapshot:snap(), now:10000, peak:new PeakTracker(), bracket:new Bracket(), session:new AlignSession()};
  const g = o => guidance({...base, ...o});
  assert.equal(g({snapshot:null}).key, 'connecting');
  assert.equal(g({snapshot:{...snap(), paused:true}}).key, 'paused');
  const cc = g({cellChange:{from:190, to:211, t:5000}});
  assert.equal(cc.key, 'cell-change'); assert.equal(cc.text, 'Now on PCI 211 (was 190). That is a different sector.');
  assert.equal(g({cellChange:{from:190, to:211, t:-5000}}).key, 'sweep');
  assert.equal(g({snapshot:{...snap(), attached:false}}).key, 'detached');
  const st = g({estimate:est({freshness:'none', ageMs:42000})});
  assert.equal(st.key, 'stale'); assert.equal(st.text, 'No fresh reading for 42 s. Check the link.');
  const first = est({freshness:'none'}); first.signal.reading = null; first.signal.raw = null;
  assert.equal(g({estimate:first}).key, 'first');
  const cap = g({capture:{status:'collecting', n:2, need:3, nQuality:0, at:10000, restartedAt:null}});
  assert.equal(cap.key, 'capture'); assert.equal(cap.text, 'Hold still: 2 of 3 readings.');
  assert.equal(g({capture:{status:'collecting', n:3, need:3, restartedAt:null}}).key, 'capture-quality');
  assert.equal(g({capture:{status:'collecting', n:0, need:3, restartedAt:8000}}).key, 'moved');
  assert.equal(g({capture:{status:'failed', n:1, need:3, at:5000}}).key, 'capture-fail');
  assert.equal(g({capture:{status:'failed', n:1, need:3, at:0}}).key, 'sweep');
  assert.equal(g({lastSaved:{index:2, t:7000}}).text, 'Position 2 saved. Adjust and compare.');
  assert.equal(g({lock:{state:'dropped', drop:2.1}}).text, 'Dropped 2.1 dB while tightening. Loosen and nudge back.');
  assert.equal(g({lock:{state:'locked'}}).key, 'locked');
  assert.equal(g({lock:{state:'watching'}}).key, 'lock');
  const br = new Bracket(); br.start(est(), {value:-80});
  assert.deepEqual([g({bracket:br}).key, g({bracket:br}).arrow], ['bracket-left', 'left']);
  assert.equal(g({estimate:est({freshness:'old', ageMs:14000})}).text, 'Last reading 14 s old. Hold still.');

  const fake = (o = {}) => ({valid:true, fitOk:true, relative:false, recommended:212, hdi68:[210, 214], theta3:60, edge:null,
    gainAt:h => 12 * (wrap180(h - 212) / 60) ** 2, pWithinAt:h => Math.abs(wrap180(h - 212)) <= 5 ? 0.95 : 0.3, ...o});
  const pose = h => ({heading:h, sd:1, valid:true, relative:false, source:'abs'});
  const turn = g({bearing:fake(), pose:pose(222)});
  assert.equal(turn.key, 'turn'); assert.equal(turn.text, 'Turn about 10° left (to 212°).'); assert.equal(turn.arrow, 'left');
  assert.match(turn.detail, /Expected gain 0\.3 dB · 30% within 0\.5 dB of the peak · beam about 60°/);
  assert.equal(g({bearing:fake(), pose:pose(150)}).detail.endsWith('Check again after you turn.'), true);
  assert.equal(g({bearing:fake(), pose:pose(200)}).arrow, 'right');
  const good = g({bearing:fake(), pose:pose(213)});
  assert.equal(good.key, 'good-enough'); assert.equal(good.text, 'Good spot. Lock it down.');
  assert.equal(g({bearing:fake({fitOk:false}), pose:pose(222)}).key, 'irregular');
  assert.equal(g({bearing:{valid:false, edge:'right'}}).text, 'Try a position further right.');

  const pk = new PeakTracker();
  [[-84, 1, 230], [-84.2, 2, 230], [-89, 3, 250], [-89.5, 4, 252]].forEach(([raw, reading, h]) => pk.offer(est({raw, reading}), pose(h)));
  const pas = g({peak:pk, estimate:est({raw:-89.5, reading:4}), pose:pose(252)});
  assert.equal(pas.key, 'passed'); assert.equal(pas.text, 'You passed the peak. Turn back about 20°.'); assert.equal(pas.arrow, 'left');
  const pas2 = g({peak:pk, estimate:est({raw:-89.5, reading:4}), pose:null});
  assert.equal(pas2.text, 'You passed the peak. Turn back to where it was strongest.');

  const s = new AlignSession();
  const b1 = s.add(pos({id:'a', index:1, signal:{mean:-82, se:0.2}})); s.add(pos({id:'b', index:2, signal:{mean:-86, se:0.2}}));
  assert.equal(g({step:'confirm', session:s, best:s.best()}).text, 'Position 1 is better. Go back to it.');
  s.positions[1].signal.mean = -82.1;
  assert.equal(g({step:'confirm', session:s, best:{position:b1, basis:'signal'}}).key, 'same');
  const at = new PeakTracker(); at.offer(est({raw:-84, reading:1})); at.offer(est({raw:-84, reading:2}));
  assert.equal(g({peak:at}).key, 'at-peak');
  assert.equal(g({estimate:est({trend:'up'})}).key, 'better');
  assert.equal(g({estimate:est({trend:'down'})}).key, 'worse');
  assert.equal(g({estimate:est({freshness:'waiting'})}).text, 'Hold still. Next reading in about 3 s.');
  const w = est({freshness:'waiting'}); w.cadence.signalEta = {p50:null, p90:null, overdue:true};
  assert.equal(g({estimate:w}).text, 'Hold still. Next reading any moment.');
  assert.deepEqual(['find', 'peak', 'confirm', 'record'].map(step => g({step}).key), ['sweep', 'nudge', 'confirm', 'record']);
});
