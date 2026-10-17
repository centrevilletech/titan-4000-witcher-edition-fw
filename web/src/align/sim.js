// Demo AlignSource: a seeded antenna/modem model that emits readings with the bench's
// bursty cadence, so the Align screen behaves in the demo as it does on a real Titan.
export const CADENCE = {
  demo:      {gapMs:[900,1600],  burst:[1,2], burstGapMs:350, qualityEvery:2},
  realistic: {gapMs:[2600,6400], burst:[2,4], burstGapMs:400, qualityEvery:3},
  fast:      {gapMs:[1000,1000], burst:[1,1], burstGapMs:0,   qualityEvery:1}
};
export const SCENARIOS = ['normal','interference','imbalance','sidelobe','slow','fast'];

const BORESIGHT = 233, THETA3 = 54, INTERFERER = 303, NOISE_FLOOR = -125;
const PRODUCING = new Set(['connected','weak','changed']);
const DETACHED = new Set(['searching','restarting']);
const wrap180 = x => ((x % 360 + 540) % 360) - 180;
const r1 = x => Math.round(x * 10) / 10;
const powerMean = list => {
  const v = list.filter(Number.isFinite);
  return v.length ? 10 * Math.log10(v.reduce((s, x) => s + 10 ** (x / 10), 0) / v.length) : null;
};

function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6D2B79F5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export class AlignSim {
  constructor({seed = Date.now(), now = () => Date.now(), manual = false} = {}) {
    this.kind = 'demo';
    this.now = now;
    this.manual = manual;
    this.rand = mulberry32(seed);
    this.controls = {quality: 72, scenario: 'connected', alignScenario: 'normal', paused: false};
    this.listeners = new Set();
    this.queue = [];
    this.timer = null;
    this.running = false;
    this.seq = 0; this.reading = 0; this.qseq = 0; this.sinceQuality = 0;
    this.signal = null; this.quality = null; this.neighbours = []; this.sccs = [];
    this.burstBase = null; this.readingT = null;
    this.eventT = now();
    this.dl = 40e6; this.ul = 5e6;
    this.poseNoise = 0;
    this.latest = null;
  }

  get profile() {
    const a = this.controls.alignScenario;
    return CADENCE[a === 'slow' ? 'realistic' : a === 'fast' ? 'fast' : 'demo'];
  }
  get heading() { return 100 + 1.6 * this.controls.quality; }
  get producing() { return PRODUCING.has(this.controls.scenario); }

  gauss(sd = 1) {
    const u = 1 - this.rand(), v = this.rand();
    return sd * Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
  }
  between([lo, hi]) { return lo + (hi - lo) * this.rand(); }
  intBetween([lo, hi]) { return lo + Math.floor(this.rand() * (hi - lo + 1)); }

  // Noise-free model at heading h and time t.
  model(h = this.heading, t = this.eventT) {
    const a = this.controls.alignScenario, e = wrap180(h - BORESIGHT);
    let L = Math.min(12 * (e / THETA3) ** 2, 20);
    // The spec's lobe sits at e = +75 (308 deg), past the slider's 260 deg limit; mirror it so the demo can reach it.
    if (a === 'sidelobe') L = Math.min(L, 14 + 12 * ((Math.abs(e) - 75) / 20) ** 2);
    const imb = a === 'imbalance' ? 8 : 2.5;
    const I = a === 'interference'
      ? -86 + (Math.floor(t / 6000) % 2 ? -4 : 4)
      : -95 - Math.min(12 * (wrap180(h - INTERFERER) / THETA3) ** 2, 20);
    const rsrp = [-80 - L, -80 - L - imb];
    return {L, I, rsrp, cinr: rsrp.map((s, c) => this.cinrOf(s - (c ? 1.5 : 0), I)), sigma: a === 'slow' ? 0.6 : 0.4};
  }
  cinrOf(s, I) { return Math.min(30, s - 10 * Math.log10(10 ** (I / 10) + 10 ** (NOISE_FLOOR / 10))); }

  start() {
    this.running = true;
    this.tick(this.now());
  }
  stop() {
    this.running = false;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }
  arm() {
    if (this.manual || !this.running) return;
    if (this.timer) clearTimeout(this.timer);
    const next = this.queue[0];
    this.timer = next ? setTimeout(() => { this.timer = null; this.tick(this.now()); }, Math.max(0, next.t - this.now())) : null;
  }
  push(t, type) {
    this.queue.push({t, type});
    this.queue.sort((a, b) => a.t - b.t);
  }

  tick(nowMs = this.now()) {
    if (!this.queue.length) this.push(nowMs, 'read');
    while (this.queue.length && this.queue[0].t <= nowMs) {
      const {t, type} = this.queue.shift();
      if (type === 'read') this.startReading(t); else this.write(t, false);
    }
    this.arm();
  }

  startReading(t) {
    const p = this.profile, n = this.intBetween(p.burst);
    this.queue = [];
    this.push(t + Math.max(this.between(p.gapMs), (n - 1) * p.burstGapMs + 1), 'read');
    if (!this.producing) return;
    for (let i = 1; i < n; i++) this.push(t + i * p.burstGapMs, 'write');
    this.reading++;
    this.readingT = t;
    const m = this.model(this.heading, t), r0 = m.rsrp[0] + this.gauss(m.sigma);
    this.burstBase = {
      rsrp: [r0, r0 - (m.rsrp[0] - m.rsrp[1]) + this.gauss(m.sigma)],
      rsrq: [0, 1].map(() => -6 - 0.08 * m.L + this.gauss(0.2))
    };
    this.write(t, true);
  }

  write(t, first) {
    if (!this.producing || !this.burstBase) return;
    this.eventT = t;
    this.seq++;
    const b = this.burstBase, jitter = first ? 0 : 0.1;
    const rsrp = b.rsrp.map(x => r1(x + (jitter && this.gauss(jitter))));
    const rsrq = b.rsrq.map(x => r1(x + (jitter && this.gauss(jitter))));
    this.signal = {seq: this.seq, reading: this.reading, t, readingT: this.readingT, rsrp, rsrq,
      rssi: rsrp.map((x, i) => r1(x + 20 - rsrq[i])), heartbeat: false, source: 'sim', periodMs: null};
    if (first && this.sinceQuality++ % this.profile.qualityEvery === 0) this.updateQuality(t, rsrp, rsrq);
    // A smoothed compass heading jitters well under its 1.5° spread; raw 1.5° per event
    // tripped Capture's 3° move test on about one reading in six (integration fix, owner i).
    this.poseNoise = this.gauss(0.5);
    this.dl = Math.min(60e6, Math.max(20e6, this.dl + this.gauss(3e6)));
    this.ul = Math.min(8e6, Math.max(2e6, this.ul + this.gauss(0.5e6)));
    this.emit(t);
  }

  updateQuality(t, rsrp, rsrq) {
    const {I} = this.model(this.heading, t);
    const cinr = rsrp.map((s, c) => r1(this.cinrOf(s - (c ? 1.5 : 0), I) + this.gauss(0.5)));
    const sinr = Math.round(powerMean(cinr));
    this.qseq++;
    this.quality = {seq: this.qseq, t, cinr, sinr, sinrStep: 1, source: 'sim'};
    this.sccs = [[1, 217, 56638, 4, 4], [2, 208, 56440, 6, 5]].map(([index, pci, earfcn, drop, cdrop]) => {
      const rsrpChains = rsrp.map(x => r1(x - drop + this.gauss(0.3)));
      const rsrqChains = rsrq.map(x => r1(x - 1 + this.gauss(0.2)));
      return {role: 'scc', index, earfcn, pci, bandwidthMhz: 20, sinr: sinr - cdrop, rsrpChains, rsrqChains,
        rssiChains: rsrpChains.map((x, i) => r1(x + 20 - rsrqChains[i])), cinrChains: cinr.map(x => r1(x - cdrop)),
        active: true, dlModulation: '64QAM', dlMcs: 17};
    });
    this.neighbours = [
      {earfcn: 56040, pci: 189, rsrp: Math.round(I), rsrq: -19, rssi: -74, coChannel: 'pcc'},
      {earfcn: 56638, pci: 216, rsrp: Math.round(-119 + this.gauss(1)), rsrq: -15, rssi: -84, coChannel: 'scc1'},
      {earfcn: 56440, pci: 207, rsrp: Math.round(-117 + this.gauss(1)), rsrq: -15, rssi: -81, coChannel: 'scc2'}
    ];
  }

  resetCell() {
    this.sinceQuality = 0;
    this.quality = null; this.signal = null; this.burstBase = null;
  }

  setControls(next = {}) {
    const prev = {...this.controls}, c = this.controls;
    for (const k of ['quality','scenario','alignScenario','paused']) if (next[k] !== undefined) c[k] = k === 'quality' ? Number(next[k]) : next[k];
    if (!SCENARIOS.includes(c.alignScenario)) c.alignScenario = 'normal';
    const t = this.now(), wasOn = PRODUCING.has(prev.scenario), pci = s => s === 'changed' ? 142 : 190;
    if (!this.producing && DETACHED.has(c.scenario)) this.resetCell();
    let fresh = false;
    if (this.producing && (!wasOn || pci(prev.scenario) !== pci(c.scenario))) { this.resetCell(); fresh = true; }
    // The slider is the installer turning the antenna: in the quick profiles the
    // quality meter follows at once (integration fix, owner i).
    if (c.quality !== prev.quality && this.profile !== CADENCE.realistic) { fresh = true; this.sinceQuality = 0; }
    if (c.alignScenario !== prev.alignScenario) this.queue = this.queue.filter(e => e.type !== 'write');
    if (fresh && this.producing && (this.running || this.manual)) { this.startReading(t); this.arm(); }
    else this.emit(t);
  }

  subscribe(fn) {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  emit(t) {
    this.latest = this.build(t);
    for (const fn of this.listeners) fn(this.latest);
  }

  snapshot() { return this.latest ?? (this.latest = this.build(this.now())); }

  build(t) {
    const c = this.controls, attached = !DETACHED.has(c.scenario), stale = c.scenario === 'stale', on = this.producing;
    const signal = attached ? this.signal : null, quality = attached ? this.quality : null;
    const collectedAt = on ? t : (this.signal?.t ?? this.eventT);
    const pccPci = c.scenario === 'changed' ? 142 : 190;
    const pcc = {role: 'pcc', index: 0, earfcn: 56040, pci: pccPci, bandwidthMhz: 20, sinr: quality?.sinr ?? null,
      rsrpChains: signal?.rsrp ?? [], rsrqChains: signal?.rsrq ?? [], rssiChains: signal?.rssi ?? [], cinrChains: quality?.cinr ?? [],
      active: true, dlModulation: stale ? null : '64QAM', dlMcs: stale ? null : 17};
    const live = on && !!signal;
    return {
      kind: 'demo', receivedAt: on ? t : collectedAt, collectedAt,
      connected: live, attached, stale, paused: !!c.paused,
      cell: attached
        ? {pci: pccPci, earfcn: 56040, band: '48', enbId: 10220, cellId: 12, tac: 10, eci: 2616332}
        : {pci: null, earfcn: null, band: null, enbId: null, cellId: null, tac: null, eci: null},
      signal, quality, activeChains: 2,
      neighbours: attached ? this.neighbours : [],
      carriers: attached ? [pcc, ...this.sccs] : [],
      radio: {cqi: stale || !attached ? null : 10, ri: stale || !attached ? null : 2, dlModulation: stale || !attached ? null : '64QAM',
        dlMcs: stale || !attached ? null : 17, ulModulation: stale || !attached ? null : '16QAM', ulMcs: stale || !attached ? null : 14,
        configured: 3, active: attached ? 3 : 0, txPowerDbm: attached ? 2 : null, mimo: attached ? 'TM4' : null},
      throughput: live ? {dlBps: Math.round(this.dl), ulBps: Math.round(this.ul)} : {dlBps: null, ulBps: null},
      sas: {grant: attached ? 'Authorized' : 'Idle', registration: 'Registered'},
      gps: {fix: true, latitude: 33.51849, longitude: -86.81036, altitudeM: 212},
      refresh: {pending: false, cycleMs: null}
    };
  }

  pose() {
    const h = this.heading;
    return {heading: (h + this.poseNoise + 360) % 360, magnetic: (h + 3.7) % 360, declination: -3.7, relative: false, sd: 1.5, tilt: 2,
      upright: true, still: true, valid: true, source: 'sim', accuracy: null, t: this.eventT};
  }

  truth() {
    const h = this.heading, m = this.model(h);
    return {heading: h, boresight: BORESIGHT, offset: wrap180(h - BORESIGHT), rsrp: m.rsrp, cinr: m.cinr};
  }
}
