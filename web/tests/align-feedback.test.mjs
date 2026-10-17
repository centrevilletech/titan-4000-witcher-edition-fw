import test from 'node:test';
import assert from 'node:assert/strict';
import * as fb from '../src/align/feedback.js';

const {PATTERNS, pitchAbsolute, pitchZoom, readingNotes, staleTickDue, STALE_TICK_MS, poseFromEuler, circularStats,
  HeadingFilter, decimalYear, declination, alabamaDeclination, wrap180, AlignAudio, Haptics, Compass, WakeLockManager} = fb;
const near = (a, b, tol, msg) => assert.ok(Math.abs(a - b) <= tol, `${msg ?? ''} ${a} !~ ${b} (±${tol})`);
const nearDeg = (a, b, tol, msg) => near(wrap180(a - b), 0, tol, msg);
const semitone = hz => 12*Math.log2(hz/440);

test('imports without window and exposes safe defaults', () => {
  assert.equal(typeof globalThis.window, 'undefined');
  assert.equal(new AlignAudio().supported, false);
  assert.equal(new Haptics().supported, false);
  assert.equal(new Haptics().pulse('mark'), false);
  assert.equal(new WakeLockManager().supported, false);
  assert.deepEqual(Compass.capabilities(), {secure:false, absEvent:false, iosPerm:false, rel:false, motion:false});
  assert.equal(new Compass().pose(), null);
});

test('PATTERNS keys exactly as specified', () => {
  assert.deepEqual(Object.keys(PATTERNS), ['better', 'worse', 'steady', 'peak', 'mark', 'fault', 'click']);
  assert.deepEqual(PATTERNS.fault, [200, 100, 200]);
  assert.deepEqual(PATTERNS.click, [8]);
});

test('pitchAbsolute spans two octaves, quantized to semitones', () => {
  assert.equal(pitchAbsolute(-120), 440);
  near(pitchAbsolute(-75), 1760, 1e-9);
  assert.equal(pitchAbsolute(-140), 440);
  near(pitchAbsolute(-50), 1760, 1e-9);
  for (let s = -120; s <= -75; s += 0.7) { const k = semitone(pitchAbsolute(s)); near(k, Math.round(k), 1e-9, `s=${s}`); }
  let prev = 0;
  for (let s = -125; s <= -70; s += 0.5) { const hz = pitchAbsolute(s); assert.ok(hz >= prev); prev = hz; }
  assert.equal(pitchAbsolute(NaN), 440);
});

test('pitchZoom: one semitone per deadband below the peak', () => {
  assert.equal(pitchZoom(0, 1), 1320);
  near(pitchZoom(12, 1), 660, 1e-9);
  near(pitchZoom(4, 2), 1320*2**(-2/12), 1e-9);
  near(pitchZoom(3, 0.5), 1320*2**(-3/12), 1e-9, 'deadband floors at 1');
  near(pitchZoom(40, 1), 1320*2**(-18/12), 1e-9, 'clamped at 18 dB');
  assert.equal(pitchZoom(-3, 1), 1320, 'above the peak is the top note');
});

test('readingNotes: motifs per trend, arpeggio on new peak, harmonic at peak', () => {
  const up = readingNotes({hz:880, trend:'up'});
  assert.deepEqual(up.map(n => n.at), [0, 110]);
  near(up[0].hz, 880*2**(-4/12), 1e-9); assert.equal(up[1].hz, 880);
  const down = readingNotes({hz:880, trend:'down'});
  near(down[0].hz, 880*2**(4/12), 1e-9); assert.equal(down[1].hz, 880);
  assert.deepEqual(readingNotes({hz:880, trend:'steady'}).map(n => n.hz), [880]);
  assert.deepEqual(readingNotes({hz:880}).map(n => n.hz), [880]);
  const peak = readingNotes({hz:440, trend:'up', newPeak:true});
  assert.deepEqual(peak.map(n => [n.at, n.dur]), [[0, 200], [90, 200], [180, 200]]);
  near(peak[2].hz, 440*2**(7/12), 1e-9);
  const at = readingNotes({hz:660, trend:'steady', atPeak:true});
  assert.deepEqual(at.map(n => [n.hz, n.gain, n.at]), [[660, 1, 0], [1320, 0.3, 0]]);
  assert.deepEqual(readingNotes({hz:0}), []);
});

test('stale tick cadence is one per 5 s', () => {
  assert.equal(STALE_TICK_MS, 5000);
  assert.equal(staleTickDue(null, 0), true);
  assert.equal(staleTickDue(1000, 5999), false);
  assert.equal(staleTickDue(1000, 6000), true);
  let ticks = 0, last = null;
  for (let t = 0; t <= 30000; t += 250) if (staleTickDue(last, t)) { ticks++; last = t; }
  assert.equal(ticks, 7);
});

test('poseFromEuler: upright phone on the panel back', () => {
  for (const alpha of [0, 90, 180, 270]) {
    const p = poseFromEuler(alpha, 90, 0);
    assert.equal(p.upright, true);
    near(p.tilt, 0, 1e-9);
    nearDeg(p.heading, (360 - alpha) % 360, 0.01, `alpha=${alpha}`);
  }
  const down = poseFromEuler(30, 80, 0);
  near(down.tilt, 10, 0.01); nearDeg(down.heading, 330, 0.01);
  assert.ok(poseFromEuler(30, 100, 0).tilt < -9.9, 'tilted back is negative');
  for (const alpha of [0, 45, 300]) {
    const flat = poseFromEuler(alpha, 0, 0);
    assert.equal(flat.upright, false);
    nearDeg(flat.heading, (360 - alpha) % 360, 0.01);
  }
  const h = poseFromEuler(0, 90, 0).heading;
  assert.ok(h >= 0 && h < 360);
});

test('circularStats across north', () => {
  const s = circularStats([359, 1]);
  nearDeg(s.mean, 0, 1e-6); assert.ok(s.mean >= 0 && s.mean < 360); assert.ok(s.sd < 1.1);
  nearDeg(circularStats([350, 10, 20]).mean, 6.5, 0.3);
  assert.equal(circularStats([42, 42, 42]).sd, 0);
  assert.deepEqual(circularStats([]), {mean:null, sd:null});
  assert.ok(circularStats([0, 180]).sd > 100);
});

test('HeadingFilter smooths across 0/360 and windows sd at 2 s', () => {
  const f = new HeadingFilter();
  for (let i = 0; i < 100; i++) f.push(i % 2 ? 358 : 2, i*20);
  nearDeg(f.heading, 0, 0.5, 'never swings through 180');
  assert.ok(f.sd() < 3);
  const g = new HeadingFilter();
  g.push(350, 0);
  for (let i = 1; i <= 60; i++) g.push(10, i*16);
  nearDeg(g.heading, 10, 0.01);
  const first = new HeadingFilter(); first.push(350, 0); first.push(10, 16);
  nearDeg(first.heading, 353, 0.1, 'EMA weight 0.15 on a unit vector');
  const w = new HeadingFilter();
  w.push(90, 0); for (let t = 2100; t <= 4000; t += 100) w.push(200, t);
  assert.equal(w.sd(), 0, 'old samples leave the 2 s window');
  w.reset(); assert.equal(w.heading, null); assert.equal(w.sd(), null);
});

test('decimalYear', () => {
  assert.equal(decimalYear(new Date(Date.UTC(2026, 0, 1))), 2026);
  near(decimalYear(new Date(Date.UTC(2026, 6, 2, 12))), 2026.5, 0.001);
});

test('WMM2025 declination matches reference values', () => {
  near(declination(33.52, -86.81, 0.2, 2026.75), -3.997, 0.01, 'Birmingham');
  near(declination(30.69, -88.04, 0.2, 2026.75), -2.956, 0.01, 'Mobile');
  near(declination(47.6, -122.3, 0.2, 2026.75), 14.866, 0.01, 'Seattle');
  assert.ok(Number.isFinite(declination(33.5, -86.8)));
});

test('alabamaDeclination tracks WMM inside the box, null outside', () => {
  for (let lat = 30.25; lat <= 35; lat += 0.95) for (let lon = -88.4; lon <= -84.8; lon += 0.9)
    near(alabamaDeclination(lat, lon, 2026.75), declination(lat, lon, 0.2, 2026.75), 0.05, `${lat},${lon}`);
  assert.equal(alabamaDeclination(29.9, -86, 2026.75), null);
  assert.equal(alabamaDeclination(36, -86, 2026.75), null);
  assert.equal(alabamaDeclination(33, -89, 2026.75), null);
  assert.equal(alabamaDeclination(47.6, -122.3, 2026.75), null);
});

test('Compass declination source order: override, then WMM at GPS, else magnetic', () => {
  const c = new Compass();
  assert.equal(c.declination, null);
  c.setLocation(33.52, -86.81, 200);
  near(c.declination, declination(33.52, -86.81, 0.2, decimalYear(new Date())), 1e-9);
  c.setDeclinationOverride(-5);
  assert.equal(c.declination, -5);
  c.setDeclinationOverride(null);
  assert.ok(c.declination < -3);
  c.setLocation(null, null);
  assert.equal(c.declination, null);
});

test('Compass picks absolute events by capability even when requestPermission exists (Chromium)', async () => {
  const handlers = {};
  const fake = (perm, abs) => ({isSecureContext:true, ...(abs ? {ondeviceorientationabsolute:null} : {}), DeviceOrientationEvent:{requestPermission:async () => perm},
    addEventListener(type, fn) { handlers[type] = fn; }, removeEventListener(type) { delete handlers[type]; }});
  try {
    globalThis.window = fake('prompt', true);
    const c = new Compass(), started = c.start();
    await new Promise(r => setTimeout(r, 10));
    assert.ok(handlers.deviceorientationabsolute, 'listens to absolute events');
    handlers.deviceorientationabsolute({alpha:90, beta:90, gamma:0, absolute:true});
    assert.equal(await started, 'abs');
    c.stop();
    globalThis.window = fake('denied', false);
    assert.equal(await new Compass().start(), 'denied', 'iOS without a grant');
  } finally { delete globalThis.window; }
});
